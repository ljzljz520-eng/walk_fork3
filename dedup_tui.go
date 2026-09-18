package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
)

// Interactive dedup mode: scan the current directory tree, browse duplicate
// groups with metadata diffs and execute journaled, recoverable merges.

type dedupTickMsg time.Time

type dedupScanDone struct {
	gen    int
	groups []*dedupGroup
	stats  dedupStats
	err    error
}

type dedupState struct {
	root   string
	width  int
	height int

	j      *dedupJournal
	merger *dedupMerger

	phase string // scanning | ready | error
	gen   int
	prog  dedupProgress
	pv    dedupProgressView

	groups []*dedupGroup
	stats  dedupStats

	gi       int
	cursor   int
	strat    dedupStrategy
	survivor map[int]int
	skipped  map[int]bool
	results  map[int]*dedupMergeResult
	kept     map[int]bool
	history  []int

	// allResults retains every merge of the session (across rescans) so
	// recovery copies can be purged on exit; purge is idempotent.
	allResults []*dedupMergeResult

	confirm  string // "" | "merge" | "all"
	showHelp bool

	msg     string
	msgWarn bool

	cancel      context.CancelFunc
	doneCh      chan dedupScanDone
	recoverInfo []string
}

func (m *model) enterDedup() tea.Cmd {
	root := m.path
	ds := &dedupState{
		root:     root,
		width:    m.termWidth,
		height:   m.termHeight,
		strat:    dedupHardlink,
		survivor: map[int]int{},
		skipped:  map[int]bool{},
		results:  map[int]*dedupMergeResult{},
		kept:     map[int]bool{},
	}

	// Reconcile interrupted jobs before creating a new journal.
	if reports, err := dedupRecover(root); err != nil {
		ds.recoverInfo = append(ds.recoverInfo, "recovery scan failed: "+err.Error())
	} else {
		for _, r := range reports {
			if len(r.Restored) > 0 {
				ds.recoverInfo = append(ds.recoverInfo,
					fmt.Sprintf("crash recovery: restored %d file(s) from %s", len(r.Restored), r.Journal))
			}
			if len(r.Conflicts) > 0 {
				ds.recoverInfo = append(ds.recoverInfo,
					fmt.Sprintf("crash recovery: %d unresolved conflict(s) under recovery/conflicts", len(r.Conflicts)))
			}
		}
	}

	j, err := newDedupJournal(root)
	if err != nil {
		ds.phase = "error"
		ds.msg = "cannot create journal under " + dedupDir(root) + ": " + err.Error()
		m.dedup = ds
		return nil
	}
	ds.j = j
	ds.merger = newDedupMerger(j)
	m.dedup = ds
	return ds.startScan()
}

func (ds *dedupState) startScan() tea.Cmd {
	ds.gen++
	gen := ds.gen
	if ds.cancel != nil {
		ds.cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	ds.cancel = cancel
	ds.phase = "scanning"
	ds.msg = ""
	ds.prog = dedupProgress{}
	ds.doneCh = make(chan dedupScanDone, 1)

	// A new tree invalidates per-group indices; on-disk merges persist.
	ds.groups = nil
	ds.stats = dedupStats{}
	ds.gi, ds.cursor = 0, 0
	ds.survivor = map[int]int{}
	ds.skipped = map[int]bool{}
	ds.results = map[int]*dedupMergeResult{}
	ds.kept = map[int]bool{}
	ds.history = nil
	ds.confirm = ""
	go func() {
		groups, stats, err := dedupScanTree(ds.root, ctx, &ds.prog)
		ds.doneCh <- dedupScanDone{gen: gen, groups: groups, stats: stats, err: err}
	}()
	return tea.Tick(120*time.Millisecond, func(time.Time) tea.Msg { return dedupTickMsg{} })
}

func (ds *dedupState) shutdown(aborted bool) {
	if ds.cancel != nil {
		ds.cancel()
	}
	if ds.j != nil {
		if !aborted {
			for _, res := range ds.allResults {
				ds.merger.purgeRecovery(res)
			}
		}
		ds.j.Close(aborted)
	}
}

// ---- key handling -------------------------------------------------------

var (
	dkeyDown      = key.NewBinding(key.WithKeys("j", "down"))
	dkeyUp        = key.NewBinding(key.WithKeys("k", "up"))
	dkeyNextGroup = key.NewBinding(key.WithKeys("l", "right", "tab"))
	dkeyPrevGroup = key.NewBinding(key.WithKeys("h", "left", "shift+tab"))
	dkeySurvivor  = key.NewBinding(key.WithKeys("s"))
	dkeyMode      = key.NewBinding(key.WithKeys("m"))
	dkeySkip      = key.NewBinding(key.WithKeys("x"))
	dkeyMerge     = key.NewBinding(key.WithKeys("enter"))
	dkeyMergeAll  = key.NewBinding(key.WithKeys("a"))
	dkeyUndo      = key.NewBinding(key.WithKeys("u"))
	dkeyRescan    = key.NewBinding(key.WithKeys("r"))
	dkeyHelp      = key.NewBinding(key.WithKeys("?"))
)

func (m *model) dedupKey(msg tea.KeyMsg) tea.Cmd {
	ds := m.dedup

	// Global: ctrl+c force-quits, keeping recovery copies for next start.
	if key.Matches(msg, keyForceQuit) {
		ds.shutdown(true)
		m.dontDoPendingDeletions()
		m.quitting = true
		m.exitCode = 2
		return tea.Quit
	}

	if ds.phase == "scanning" {
		if key.Matches(msg, keyQuit) {
			ds.shutdown(true)
			m.dedup = nil
			m.list()
		}
		return nil
	}

	if key.Matches(msg, dkeyHelp) {
		ds.showHelp = !ds.showHelp
		return nil
	}
	if ds.showHelp {
		ds.showHelp = false
		return nil
	}

	if key.Matches(msg, keyQuit, keyQuitQ) {
		ds.shutdown(false)
		m.dedup = nil
		m.list()
		return nil
	}

	if ds.phase == "error" {
		return nil
	}

	g := ds.currentGroup()
	if g == nil {
		if key.Matches(msg, dkeyRescan) {
			return ds.startScan()
		}
		return nil
	}

	ds.msg, ds.msgWarn = "", false

	switch {
	case key.Matches(msg, dkeyUp):
		if ds.cursor > 0 {
			ds.cursor--
		}
		ds.confirm = ""
	case key.Matches(msg, dkeyDown):
		if ds.cursor < len(g.Files)-1 {
			ds.cursor++
		}
		ds.confirm = ""
	case key.Matches(msg, dkeyPrevGroup):
		if ds.gi > 0 {
			ds.gi--
			ds.cursor = clamp(ds.survivor[ds.gi], 0, len(ds.groups[ds.gi].Files)-1)
		}
		ds.confirm = ""
	case key.Matches(msg, dkeyNextGroup):
		if ds.gi < len(ds.groups)-1 {
			ds.gi++
			ds.cursor = clamp(ds.survivor[ds.gi], 0, len(ds.groups[ds.gi].Files)-1)
		}
		ds.confirm = ""
	case key.Matches(msg, dkeySurvivor):
		if _, merged := ds.results[ds.gi]; !merged {
			ds.survivor[ds.gi] = ds.cursor
		}
		ds.confirm = ""
	case key.Matches(msg, dkeyMode):
		ds.strat = (ds.strat + 1) % 4
		ds.confirm = ""
	case key.Matches(msg, dkeySkip):
		ds.skipped[ds.gi] = !ds.skipped[ds.gi]
		ds.confirm = ""
	case key.Matches(msg, dkeyUndo):
		ds.undoCurrent()
		ds.confirm = ""
	case key.Matches(msg, dkeyRescan):
		return ds.startScan()
	case key.Matches(msg, dkeyMerge):
		if ds.confirm == "merge" {
			ds.confirm = ""
			ds.mergeCurrent()
		} else {
			ds.confirm = "merge"
		}
	case key.Matches(msg, dkeyMergeAll):
		if ds.confirm == "all" {
			ds.confirm = ""
			ds.mergeAll()
		} else {
			ds.confirm = "all"
		}
	}
	return nil
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func (ds *dedupState) currentGroup() *dedupGroup {
	if ds.gi < 0 || ds.gi >= len(ds.groups) {
		return nil
	}
	return ds.groups[ds.gi]
}

func (ds *dedupState) mergeCurrent() {
	g := ds.currentGroup()
	if g == nil {
		return
	}
	if _, done := ds.results[ds.gi]; done {
		ds.setMsg("already merged; press u to undo", true)
		return
	}
	if ds.skipped[ds.gi] {
		ds.setMsg("group skipped; press x to include", true)
		return
	}
	if ds.strat == dedupKeep {
		ds.kept[ds.gi] = true
		ds.setMsg("kept independent copies", false)
		return
	}
	sur := ds.survivor[ds.gi]
	res, err := ds.merger.merge(g, sur, ds.strat)
	if err != nil {
		ds.setMsg("merge failed (rolled back): "+err.Error(), true)
		return
	}
	if res != nil {
		ds.results[ds.gi] = res
		ds.history = append(ds.history, ds.gi)
		ds.allResults = append(ds.allResults, res)
		msg := fmt.Sprintf("merged %d path(s) via %s", len(res.Steps), ds.strat)
		if len(res.AlreadyLinked) > 0 {
			msg += fmt.Sprintf(", %d already linked", len(res.AlreadyLinked))
		}
		if len(res.Warnings) > 0 {
			msg += "  ⚠ " + res.Warnings[0]
			ds.setMsg(msg, true)
		} else {
			ds.setMsg(msg, false)
		}
	}
}

func (ds *dedupState) mergeAll() {
	var merged, failed, skipped int
	for gi, g := range ds.groups {
		if _, done := ds.results[gi]; done || ds.skipped[gi] || ds.kept[gi] {
			skipped++
			continue
		}
		if ds.strat == dedupKeep {
			ds.kept[gi] = true
			skipped++
			continue
		}
		res, err := ds.merger.merge(g, ds.survivor[gi], ds.strat)
		if err != nil {
			failed++
			ds.setMsg(fmt.Sprintf("merge-all stopped at group %d: %v (others rolled back safely)", gi+1, err), true)
			return
		}
		if res != nil && len(res.Steps) > 0 {
			ds.results[gi] = res
			ds.history = append(ds.history, gi)
			ds.allResults = append(ds.allResults, res)
			merged++
		}
	}
	ds.setMsg(fmt.Sprintf("merge-all: %d group(s) merged, %d skipped, %d failed", merged, skipped, failed), failed > 0)
}

func (ds *dedupState) undoCurrent() {
	gi := ds.gi
	res, ok := ds.results[gi]
	if !ok {
		// Undo the most recently merged group.
		for i := len(ds.history) - 1; i >= 0; i-- {
			if r, exists := ds.results[ds.history[i]]; exists {
				gi, res, ok = ds.history[i], r, true
				break
			}
		}
	}
	if !ok {
		ds.setMsg("nothing to undo", true)
		return
	}
	g := ds.groups[gi]
	warnings, err := ds.merger.undo(g, res)
	if err != nil {
		ds.setMsg("undo failed: "+err.Error(), true)
		return
	}
	delete(ds.results, gi)
	ds.merger.purgeRecovery(res)
	for i := len(ds.history) - 1; i >= 0; i-- {
		if ds.history[i] == gi {
			ds.history = append(ds.history[:i], ds.history[i+1:]...)
			break
		}
	}
	msg := "undone: independent copies restored"
	if len(warnings) > 0 {
		msg += "  ⚠ " + strings.Join(warnings, "; ")
		ds.setMsg(msg, true)
	} else {
		ds.setMsg(msg, false)
	}
}

func (ds *dedupState) setMsg(s string, warn bool) {
	ds.msg, ds.msgWarn = s, warn
}

// ---- tick / async completion -------------------------------------------

func (m *model) dedupTick() tea.Cmd {
	ds := m.dedup
	ds.pv = ds.prog.view()
	select {
	case done := <-ds.doneCh:
		if done.gen != ds.gen {
			break // stale scan
		}
		if done.err != nil {
			if done.err == context.Canceled {
				return nil
			}
			ds.phase = "error"
			ds.msg = "scan failed: " + done.err.Error()
			return nil
		}
		ds.groups, ds.stats, ds.phase = done.groups, done.stats, "ready"
		ds.gi, ds.cursor = 0, 0
		_ = ds.j.Log(dedupRecord{
			Type: recScanStats, Walked: done.stats.Walked,
			Groups: len(done.groups),
		})
		if len(done.groups) == 0 {
			ds.setMsg("no duplicate content found under "+ds.root, false)
		} else {
			ds.setMsg(fmt.Sprintf("%d duplicate group(s), %s potentially reclaimable",
				len(done.groups), dedupHumanSize(done.stats.Wasted)), false)
		}
		return nil
	default:
	}
	return tea.Tick(120*time.Millisecond, func(time.Time) tea.Msg { return dedupTickMsg{} })
}

// ---- view ---------------------------------------------------------------

func (m *model) dedupView() string {
	ds := m.dedup
	w := max(ds.width, 40)
	h := max(ds.height, 5)

	var b strings.Builder

	title := " dedup: " + ds.shortRoot()
	title = dedupPadEnd(title, w)
	b.WriteString(bar.Render(title) + "\n")

	switch ds.phase {
	case "scanning":
		ds.renderScanning(&b, w, h-1)
	case "error":
		b.WriteString(warning.Render(ds.msg))
		b.WriteString("\n\nesc back")
	case "ready":
		if ds.showHelp {
			ds.renderHelp(&b, w, h-1)
		} else {
			ds.renderReady(&b, w, h-1)
		}
	}

	out := b.String()
	if m.quitting {
		out += "\n"
	}
	return out
}

func (ds *dedupState) shortRoot() string {
	root := ds.root
	if home, err := os.UserHomeDir(); err == nil {
		root = strings.Replace(root, home, "~", 1)
	}
	return root
}

func (ds *dedupState) renderScanning(b *strings.Builder, w, rows int) {
	pv := ds.prog.view()
	fmt.Fprintf(b, "scanning…  phase: %s\n", pv.Phase)
	fmt.Fprintf(b, "files walked: %d   hashes: %d   candidate files: %d\n", pv.Walked, pv.Hashing, pv.Buckets)
	cur := dedupClip("now: "+pv.Current, w-1)
	b.WriteString(cur + "\n")
	for _, info := range ds.recoverInfo {
		b.WriteString(dedupClip(info, w-1) + "\n")
	}
	b.WriteString("\nesc cancel")
}

func (ds *dedupState) renderReady(b *strings.Builder, w, rows int) {
	g := ds.currentGroup()
	if g == nil {
		b.WriteString("no groups\n\nr rescan    esc exit")
		return
	}

	sur := ds.survivor[ds.gi]
	linked := 0
	for i := range g.Files {
		if g.isLinkedWithSurvivor(i, sur) {
			linked++
		}
	}

	// Group header.
	header := fmt.Sprintf("group %d/%d  size %s  sha256 %s…  %d paths",
		ds.gi+1, len(ds.groups), dedupHumanSize(g.Size), g.Hash[:12], len(g.Files))
	if linked > 0 {
		header += fmt.Sprintf("  (%d already hardlinked)", linked)
	}
	if ds.skipped[ds.gi] {
		header += "  [SKIP]"
	}
	if _, merged := ds.results[ds.gi]; merged {
		header += "  [MERGED]"
	}
	if ds.kept[ds.gi] {
		header += "  [KEEP]"
	}
	b.WriteString(dedupClip(header, w-1) + "\n")

	// Reserve lines for diff block + footer.
	diffLines, _ := ds.buildDiff(g, sur, w)
	footer := 3
	if ds.confirm != "" {
		footer++
	}
	if ds.msg != "" {
		footer++
	}
	maxRows := rows - 1 - len(diffLines) - footer
	maxRows = max(maxRows, 1)

	start, end := 0, len(g.Files)
	if ds.cursor >= maxRows {
		start = ds.cursor - maxRows + 1
	}
	if end-start > maxRows {
		end = start + maxRows
	}

	for i := start; i < end; i++ {
		line, full := ds.renderFileRow(g, i, sur, w)
		if !full {
			line = dedupClip(line, w-1)
		}
		if i == ds.cursor {
			line = cursor.Render(dedupPadEnd(line, w-1))
		}
		b.WriteString(line + "\n")
	}

	for _, l := range diffLines {
		b.WriteString(l + "\n")
	}

	b.WriteString("\n")
	// Strategy selector.
	var modes [4]string
	for i, s := range []dedupStrategy{dedupHardlink, dedupReflink, dedupCAS, dedupKeep} {
		name := s.String()
		if s == ds.strat {
			modes[i] = "[" + name + "]"
		} else {
			modes[i] = " " + name + " "
		}
	}
	b.WriteString(dedupClip("mode "+strings.Join(modes[:], " "), w-1) + "\n")

	if ds.confirm == "merge" {
		b.WriteString(danger.Render("press enter again to merge this group — original copies stay recoverable (u)") + "\n")
	} else if ds.confirm == "all" {
		b.WriteString(danger.Render("press a again to merge every unskipped group") + "\n")
	}
	if ds.msg != "" {
		style := bar
		if ds.msgWarn {
			style = warning
		}
		b.WriteString(style.Render(dedupClip(ds.msg, w-3)) + "\n")
	}
	b.WriteString(dedupClip("hjkl move · s survivor · m mode · enter merge · a all · x skip · u undo · r rescan · ? help · esc exit", w-1))
}

func (ds *dedupState) renderFileRow(g *dedupGroup, i, sur, w int) (string, bool) {
	f := g.Files[i]
	mark := " "
	switch {
	case i == sur:
		mark = "*"
	case g.isLinkedWithSurvivor(i, sur):
		mark = "="
	case ds.kept[ds.gi]:
		mark = "k"
	case ds.skipped[ds.gi]:
		mark = "x"
	}
	if _, merged := ds.results[ds.gi]; merged && mark == " " {
		mark = "✓"
	}

	rel, err := filepath.Rel(ds.root, f.Path)
	if err != nil {
		rel = f.Path
	}

	hole := fmt.Sprintf("hole:%3.0f%%", f.holePct())
	owner := fmt.Sprintf("%d:%d", f.Uid, f.Gid)
	xsum := fmt.Sprintf("x:%d", len(f.XAttrs))
	if i != sur {
		onlyS, onlyH, changed := dedupXAttrDiff(g.Files[sur].XAttrs, f.XAttrs)
		if len(onlyS)+len(onlyH)+len(changed) > 0 {
			xsum = fmt.Sprintf("x:%d!", len(f.XAttrs))
		}
	}
	acl := "acl:n/a"
	if f.ACL.Available {
		if f.ACL.Present {
			acl = fmt.Sprintf("acl:%d", f.ACL.Entries)
		} else {
			acl = "acl: -"
		}
	}

	head := fmt.Sprintf("%s ino:%-8d n:%d %s %s %s %s %s %s  ",
		mark, f.Ino, f.Nlink, hole, dedupModeString(f.Mode.Perm()), owner,
		dedupFmtTime(f.Mtime), xsum, acl)

	pathWidth := w - 1 - strlen(head)
	path := rel
	full := true
	if pathWidth < 10 {
		path = ""
	} else if strlen(path) > pathWidth {
		path = "…" + dedupClipLeft(path, pathWidth-1)
		full = false
	}
	return head + path, full
}

// buildDiff renders the metadata difference between the cursor row and the
// survivor row.
func (ds *dedupState) buildDiff(g *dedupGroup, sur, w int) ([]string, bool) {
	if len(g.Files) < 2 || ds.cursor == sur {
		return nil, false
	}
	s, o := g.Files[sur], g.Files[ds.cursor]
	if s.identityKey() == o.identityKey() {
		return []string{"= same inode as survivor — no merge needed"}, true
	}

	var lines []string
	add := func(format string, args ...any) {
		lines = append(lines, dedupClip("  "+fmt.Sprintf(format, args...), w-1))
	}

	add("diff vs survivor:")
	if s.Mtime.Equal(o.Mtime) {
		add("mtime  same (%s)", dedupFmtTime(s.Mtime))
	} else {
		add("mtime  survivor %s · here %s (%s)",
			dedupFmtTime(s.Mtime), dedupFmtTime(o.Mtime), dedupDur(o.Mtime.Sub(s.Mtime)))
	}
	if s.Mode.Perm() == o.Mode.Perm() {
		add("mode   same (%s)", dedupModeString(s.Mode.Perm()))
	} else {
		add("mode   %s → %s", dedupModeString(s.Mode.Perm()), dedupModeString(o.Mode.Perm()))
	}
	if s.Uid == o.Uid && s.Gid == o.Gid {
		add("owner  same (%d:%d)", s.Uid, s.Gid)
	} else {
		add("owner  %d:%d → %d:%d", s.Uid, s.Gid, o.Uid, o.Gid)
	}
	sh, oh := s.holePct(), o.holePct()
	if sh == oh {
		add("hole   same (%.0f%%)", sh)
	} else {
		add("hole   survivor %.0f%% · here %.0f%%", sh, oh)
	}
	onlyS, onlyH, changed := dedupXAttrDiff(s.XAttrs, o.XAttrs)
	if len(onlyS) == 0 && len(onlyH) == 0 && len(changed) == 0 {
		add("xattr  same (%d keys)", len(s.XAttrs))
	} else {
		if len(onlyS) > 0 {
			add("xattr  only on survivor: %s", strings.Join(onlyS, ","))
		}
		if len(onlyH) > 0 {
			add("xattr  only here: %s", strings.Join(onlyH, ","))
		}
		if len(changed) > 0 {
			add("xattr  value differs: %s", strings.Join(changed, ","))
		}
	}
	switch {
	case !s.ACL.Available || !o.ACL.Available:
		add("acl    n/a on this platform")
	case s.ACL.Hash == o.ACL.Hash:
		add("acl    same (entries: %d)", s.ACL.Entries)
	default:
		sp, op := "-", "-"
		if s.ACL.Present {
			sp = fmt.Sprintf("%d entries", s.ACL.Entries)
		}
		if o.ACL.Present {
			op = fmt.Sprintf("%d entries", o.ACL.Entries)
		}
		add("acl    survivor %s · here %s", sp, op)
	}

	if ds.strat == dedupHardlink || ds.strat == dedupCAS {
		add("note   %s unifies metadata onto the survivor inode", ds.strat)
	} else {
		add("note   reflink keeps an independent inode; victim metadata is restored")
	}
	return lines, true
}

func (ds *dedupState) renderHelp(b *strings.Builder, w, rows int) {
	keys := [][2]string{
		{"j/k, ↑/↓", "move between paths"},
		{"h/l, ←/→", "prev/next duplicate group"},
		{"s", "mark current path as survivor (metadata winner)"},
		{"m", "cycle mode: hardlink / reflink / cas / keep"},
		{"enter", "merge current group (press twice)"},
		{"a", "merge every unskipped group (press twice)"},
		{"x", "skip/include current group in merge-all"},
		{"u", "undo merge (recovery copies retained until exit)"},
		{"r", "rescan tree"},
		{"?", "close help"},
		{"esc/q", "leave dedup, purge verified recovery copies"},
		{"ctrl+c", "quit immediately; journal reconciles on next start"},
	}
	b.WriteString("dedup help\n\n")
	for _, kv := range keys {
		line := fmt.Sprintf("  %-10s  %s", kv[0], kv[1])
		b.WriteString(dedupClip(line, w-1) + "\n")
	}
	b.WriteString("\njournal and recovery copies live in " + dedupDir(ds.root) + "\n")
}

// ---- small formatting helpers ------------------------------------------

func dedupDur(d time.Duration) string {
	if d < 0 {
		return "-" + dedupDur(-d)
	}
	if d < time.Minute {
		return d.Round(time.Second).String()
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
}

func dedupClip(s string, w int) string {
	if strlen(s) <= w {
		return s
	}
	r := []rune(s)
	width := 0
	for i := len(r) - 1; i >= 0; i-- {
		width += strlen(string(r[i]))
		if width > w {
			return string(r[i+1:])
		}
	}
	return string(r)
}

func dedupClipLeft(s string, w int) string {
	if strlen(s) <= w {
		return s
	}
	r := []rune(s)
	width, out := 0, make([]rune, 0, w)
	for i := len(r) - 1; i >= 0; i-- {
		cw := strlen(string(r[i]))
		if width+cw > w {
			break
		}
		width += cw
		out = append([]rune{r[i]}, out...)
	}
	return string(out)
}

func dedupPadEnd(s string, w int) string {
	pad := w - strlen(s)
	if pad <= 0 {
		return s
	}
	return s + strings.Repeat(" ", pad)
}
