//go:build linux || darwin

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTestFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
}

func hashHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	id, err := dedupIdentify(path)
	if err != nil {
		t.Fatal(err)
	}
	return id.Ino
}

func scanGroups(t *testing.T, root string) []*dedupGroup {
	t.Helper()
	var prog dedupProgress
	groups, _, err := dedupScanTree(root, context.Background(), &prog)
	if err != nil {
		t.Fatal(err)
	}
	return groups
}

// findGroupByHash returns the group whose hash matches the content.
func findGroupByHash(groups []*dedupGroup, h string) *dedupGroup {
	for _, g := range groups {
		if g.Hash == h {
			return g
		}
	}
	return nil
}

func newTestJournal(t *testing.T, root string) *dedupJournal {
	t.Helper()
	j, err := newDedupJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

// ---- phase 1-3 detection ------------------------------------------------

func TestDedupScanThreePhases(t *testing.T) {
	root := t.TempDir()

	// 20KB content: bigger than 2*quick sample so full hash is exercised.
	big := make([]byte, 20*1024)
	for i := range big {
		big[i] = byte(i % 251)
	}
	// Same size, same prefix, different tail: must be split at full hash.
	bigTail := append([]byte(nil), big...)
	bigTail[len(bigTail)-1] ^= 0xFF

	small := []byte("hello world")
	empty := []byte{}

	writeTestFile(t, filepath.Join(root, "a", "f1"), big)
	writeTestFile(t, filepath.Join(root, "sub", "f2"), big)
	writeTestFile(t, filepath.Join(root, "sub", "f3_suffix"), bigTail)
	writeTestFile(t, filepath.Join(root, "b", "f4"), small)
	writeTestFile(t, filepath.Join(root, "c", "f5"), small)
	writeTestFile(t, filepath.Join(root, "e1"), empty)
	writeTestFile(t, filepath.Join(root, "nested", "dir", "e2"), empty)

	groups := scanGroups(t, root)

	if g := findGroupByHash(groups, hashHex(big)); g == nil {
		t.Fatal("missing group for large duplicated content")
	} else if len(g.Files) != 2 {
		t.Fatalf("big group: want 2 files, got %d", len(g.Files))
	}
	if g := findGroupByHash(groups, hashHex(small)); g == nil || len(g.Files) != 2 {
		t.Fatal("missing/sized group for small duplicates")
	}
	if g := findGroupByHash(groups, hashHex(empty)); g == nil || len(g.Files) != 2 {
		t.Fatal("missing group for empty duplicates")
	}
	if g := findGroupByHash(groups, hashHex(bigTail)); g != nil {
		t.Fatal("tail-different file must not form a duplicate group")
	}
}

func TestDedupSkipsSymlinksAndOwnDir(t *testing.T) {
	root := t.TempDir()
	content := []byte("symlink test content xxxxx")
	writeTestFile(t, filepath.Join(root, "real"), content)
	// Symlink with same "size" should be ignored entirely.
	if err := os.Symlink("real", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	// Something inside .walk-dedup that looks identical must not be scanned.
	writeTestFile(t, filepath.Join(root, dedupDirName, "recovery", "x"), content)

	groups := scanGroups(t, root)
	if g := findGroupByHash(groups, hashHex(content)); g != nil {
		t.Fatalf("symlink/dedup-dir content must be excluded, got group with %d", len(g.Files))
	}
}

// ---- metadata: xattr diff + sparseness ----------------------------------

func TestDedupMetadataXAttrAndSparse(t *testing.T) {
	root := t.TempDir()
	content := make([]byte, 64*1024)
	for i := range content {
		content[i] = byte(i * 7)
	}
	// Apparent content: a 1MB zero prefix (a hole in the sparse copy) plus
	// the 64KB tail — identical bytes for both members.
	bigSize := int64(1024 * 1024)
	full := append(make([]byte, bigSize), content...)
	plain := filepath.Join(root, "plain")
	sparse := filepath.Join(root, "sparse")
	writeTestFile(t, plain, full)

	// Sparse file: same content, but the zero prefix is a hole.
	f, err := os.OpenFile(sparse, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt(content, bigSize); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	groups := scanGroups(t, root)
	var g *dedupGroup
	for _, gr := range groups {
		if gr.Size == bigSize+int64(len(content)) {
			g = gr
		}
	}
	if g == nil {
		t.Fatal("sparse duplicate group not found")
	}
	if len(g.Files) != 2 {
		t.Fatalf("want 2 members, got %d", len(g.Files))
	}

	// Put an xattr on one member; the diff must surface it.
	if err := dedupSetXAttrForTest(plain, "user.walktest", []byte("ping")); err != nil {
		t.Skipf("xattr not supported here: %v", err)
	}
	groups = scanGroups(t, root)
	g = nil
	for _, gr := range groups {
		if gr.Size == bigSize+int64(len(content)) {
			g = gr
		}
	}
	var withAttr, withoutAttr *dedupMeta
	for _, mt := range g.Files {
		if xa, ok := mt.XAttrs["user.walktest"]; ok && xa.Hash != "" {
			withAttr = mt
		}
		if _, ok := mt.XAttrs["user.walktest"]; !ok {
			withoutAttr = mt
		}
	}
	if withAttr == nil || withoutAttr == nil {
		t.Fatal("xattr not observed on exactly one group member")
	}
	onlyA, onlyB, changed := dedupXAttrDiff(withAttr.XAttrs, withoutAttr.XAttrs)
	if len(onlyA) != 1 || onlyA[0] != "user.walktest" {
		t.Fatalf("xattr diff wrong: %v %v %v", onlyA, onlyB, changed)
	}
	if withAttr.holePct() < 0 || withoutAttr.holePct() > 0 {
		t.Fatalf("sparseness unexpected: with=%f without=%f", withAttr.holePct(), withoutAttr.holePct())
	}
}

// ---- hardlink merge + undo ----------------------------------------------

func makePair(t *testing.T, root, nameA, nameB string, content []byte, oldTime time.Time) (string, string) {
	a := filepath.Join(root, nameA)
	b := filepath.Join(root, "d", nameB)
	writeTestFile(t, a, content)
	writeTestFile(t, b, content)
	if !oldTime.IsZero() {
		if err := os.Chtimes(b, oldTime, oldTime); err != nil {
			t.Fatal(err)
		}
	}
	return a, b
}

func TestDedupHardlinkMergeAndUndo(t *testing.T) {
	root := t.TempDir()
	old := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	content := []byte("hardlink merge content — slightly longer than quick sample padding padding")
	a, b := makePair(t, root, "a", "b", content, old)

	groups := scanGroups(t, root)
	g := findGroupByHash(groups, hashHex(content))
	if g == nil {
		t.Fatal("group not found")
	}
	j := newTestJournal(t, root)
	mg := newDedupMerger(j)

	res, err := mg.merge(g, 0, dedupHardlink)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Steps) != 1 {
		t.Fatalf("want 1 step, got %d", len(res.Steps))
	}
	if inodeOf(t, a) != inodeOf(t, b) {
		t.Fatal("a and b were not hardlinked")
	}
	if got, _ := os.ReadFile(b); string(got) != string(content) {
		t.Fatal("content mismatch after merge")
	}
	if _, err := os.Stat(res.Steps[0].Recovery); err != nil {
		t.Fatalf("recovery copy should be retained after commit: %v", err)
	}

	// Journal recorded the full lifecycle.
	recs := j.Records()
	wantTypes := map[string]bool{
		recMergeBegin: false, recVictimStage: false, recVictimReplace: false,
		recVictimVerify: false, recMergeCommit: false,
	}
	for _, r := range recs {
		if _, ok := wantTypes[r.Type]; ok {
			wantTypes[r.Type] = true
		}
	}
	for typ, seen := range wantTypes {
		if !seen {
			t.Errorf("journal missing %s", typ)
		}
	}

	// Undo restores an independent inode while keeping identical content.
	if _, err := mg.undo(g, res); err != nil {
		t.Fatal(err)
	}
	if inodeOf(t, a) == inodeOf(t, b) {
		t.Fatal("undo did not restore independent inode")
	}
	if got, _ := os.ReadFile(b); string(got) != string(content) {
		t.Fatal("content changed after undo")
	}
	j.Close(false)
}

func TestDedupHardlinkSkipsAlreadyLinked(t *testing.T) {
	root := t.TempDir()
	content := []byte("already linked pair")
	a := filepath.Join(root, "a")
	b := filepath.Join(root, "b")
	writeTestFile(t, a, content)
	if err := os.Link(a, b); err != nil {
		t.Fatal(err)
	}
	groups := scanGroups(t, root)
	g := findGroupByHash(groups, hashHex(content))
	if g == nil {
		t.Fatal("group not found")
	}
	j := newTestJournal(t, root)
	mg := newDedupMerger(j)
	res, err := mg.merge(g, 0, dedupHardlink)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Steps) != 0 || len(res.AlreadyLinked) != 1 {
		t.Fatalf("expected skip of pre-linked pair, got steps=%d linked=%d", len(res.Steps), len(res.AlreadyLinked))
	}
	j.Close(false)
}

// ---- CAS ----------------------------------------------------------------

func TestDedupCASMerge(t *testing.T) {
	root := t.TempDir()
	content := make([]byte, 30*1024)
	for i := range content {
		content[i] = byte(i % 199)
	}
	a := filepath.Join(root, "a")
	b := filepath.Join(root, "deep", "b")
	writeTestFile(t, a, content)
	writeTestFile(t, b, content)

	groups := scanGroups(t, root)
	g := findGroupByHash(groups, hashHex(content))
	j := newTestJournal(t, root)
	mg := newDedupMerger(j)

	res, err := mg.merge(g, 0, dedupCAS)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Steps) != 2 {
		t.Fatalf("cas replaces survivor + victim, want 2 steps, got %d", len(res.Steps))
	}
	obj := filepath.Join(j.CASDir(), g.Hash[0:2], g.Hash[2:4], g.Hash)
	if !pathHasContent(obj, g.Hash) {
		t.Fatal("cas object missing or corrupt")
	}
	objIno := inodeOf(t, obj)
	if inodeOf(t, a) != objIno || inodeOf(t, b) != objIno {
		t.Fatal("paths are not linked to the cas object")
	}

	// A second identical group reuses the object idempotently.
	root2 := root // same store
	c := filepath.Join(root2, "deep", "c")
	writeTestFile(t, c, content)
	groups = scanGroups(t, root)
	g = findGroupByHash(groups, hashHex(content))
	if _, err := mg.merge(g, 0, dedupCAS); err != nil {
		t.Fatal(err)
	}
	if inodeOf(t, c) != objIno {
		t.Fatal("cas object not reused")
	}
	j.Close(false)
}

// ---- reflink -------------------------------------------------------------

func TestDedupReflinkMerge(t *testing.T) {
	root := t.TempDir()
	old := time.Date(2002, 3, 4, 5, 6, 7, 0, time.UTC)
	content := make([]byte, 40*1024)
	for i := range content {
		content[i] = byte(i % 197)
	}
	a, b := makePair(t, root, "a", "b", content, old)
	xattrOK := dedupSetXAttrForTest(b, "user.walkclone", []byte("v1")) == nil

	groups := scanGroups(t, root)
	g := findGroupByHash(groups, hashHex(content))
	j := newTestJournal(t, root)
	mg := newDedupMerger(j)

	res, err := mg.merge(g, 0, dedupReflink)
	if err != nil {
		if errors.Is(err, errDedupReflinkUnsupported) {
			t.Skipf("reflink unsupported on this filesystem: %v", err)
		}
		t.Fatal(err)
	}
	if len(res.Steps) != 1 {
		t.Fatalf("want 1 step, got %d (warnings %v)", len(res.Steps), res.Warnings)
	}
	if inodeOf(t, a) == inodeOf(t, b) {
		t.Fatal("reflink clone shares the survivor inode")
	}
	if got, _ := os.ReadFile(b); string(got) != string(content) {
		t.Fatal("clone content mismatch")
	}
	if fi, err := os.Stat(b); err != nil || fi.ModTime().IsZero() {
		t.Fatal("clone stat failed")
	} else if !fi.ModTime().Equal(old) {
		t.Fatalf("victim mtime not restored: %v", fi.ModTime())
	}
	if xattrOK {
		xa := dedupReadXAttrSummaries(b)
		if v, ok := xa["user.walkclone"]; !ok || v.Hash != hashHex([]byte("v1")) {
			t.Fatalf("victim xattr not restored: %+v", xa)
		}
	}
	j.Close(false)
}

// ---- re-verification safety ---------------------------------------------

func TestDedupAbortsWhenContentChanged(t *testing.T) {
	root := t.TempDir()
	content := make([]byte, 30*1024)
	for i := range content {
		content[i] = byte(i % 193)
	}
	a, b := makePair(t, root, "a", "b", content, time.Time{})

	groups := scanGroups(t, root)
	g := findGroupByHash(groups, hashHex(content))

	// Same-size rewrite of b between scan and merge: inode/size checks pass,
	// the open-descriptor full-hash re-verification must catch it.
	tampered := make([]byte, len(content))
	copy(tampered, content)
	for i := 0; i < 1024; i++ {
		tampered[i] ^= 0xAA
	}
	if err := os.WriteFile(b, tampered, 0o644); err != nil {
		t.Fatal(err)
	}

	j := newTestJournal(t, root)
	mg := newDedupMerger(j)
	res, err := mg.merge(g, 0, dedupHardlink)
	if err == nil {
		t.Fatal("merge must fail after tampering")
	}
	if !errors.Is(err, errDedupChanged) {
		t.Fatalf("want errDedupChanged, got %v", err)
	}
	if inodeOf(t, a) == inodeOf(t, b) {
		t.Fatal("nothing must be linked after a failed merge")
	}
	if got, _ := os.ReadFile(b); string(got) != string(tampered) {
		t.Fatal("victim must stay untouched after abort")
	}
	if res != nil && len(res.Steps) != 0 {
		t.Fatal("no steps should be retained after pre-stage abort")
	}
	// Journal records the rollback.
	var rolledBack bool
	for _, r := range j.Records() {
		if r.Type == recMergeRollback {
			rolledBack = true
		}
	}
	if rolledBack {
		t.Fatal("rollback should not be journaled when nothing was staged")
	}
	j.Close(false)
}

// ---- journal + crash recovery -------------------------------------------

func TestDedupRecoverCommittedPurgesCopy(t *testing.T) {
	root := t.TempDir()
	content := []byte("committed merge recovery content padding padding padding")
	a, b := makePair(t, root, "a", "b", content, time.Time{})

	groups := scanGroups(t, root)
	g := findGroupByHash(groups, hashHex(content))
	j := newTestJournal(t, root)
	mg := newDedupMerger(j)
	res, err := mg.merge(g, 0, dedupHardlink)
	if err != nil {
		t.Fatal(err)
	}
	recovery := res.Steps[0].Recovery
	j.Close(false)

	if _, err := os.Stat(recovery); err != nil {
		t.Fatal("recovery copy missing before reconcile")
	}
	reports, err := dedupRecover(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 || len(reports[0].Purged) != 1 {
		t.Fatalf("unexpected recover reports: %+v", reports)
	}
	if _, err := os.Stat(recovery); !os.IsNotExist(err) {
		t.Fatal("recovery copy should be purged after committed reconcile")
	}
	if inodeOf(t, a) != inodeOf(t, b) {
		t.Fatal("committed links must survive reconcile")
	}
	// Journal marked as processed (renamed to *.done.jsonl).
	entries, _ := os.ReadDir(dedupDir(root))
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, "journal-") && strings.HasSuffix(n, ".jsonl") && !strings.HasSuffix(n, ".done.jsonl") {
			t.Fatalf("journal not archived: %s", n)
		}
	}
}

func TestDedupRecoverInterruptedRestoresVictim(t *testing.T) {
	root := t.TempDir()
	content := []byte("interrupted before commit victim content padding padding")
	a, b := makePair(t, root, "a", "b", content, time.Time{})
	h := hashHex(content)

	j := newTestJournal(t, root)
	rp, err := j.recoveryPath(1, b)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Log(dedupRecord{Type: recMergeBegin, Seq: 1, Hash: h, Survivor: a}); err != nil {
		t.Fatal(err)
	}
	// Stage the victim, then "crash": no replacement, no verify, no commit.
	if err := os.Rename(b, rp); err != nil {
		t.Fatal(err)
	}
	if err := j.Log(dedupRecord{
		Type: recVictimStage, Seq: 1, Path: b, Recovery: rp, Hash: h,
	}); err != nil {
		t.Fatal(err)
	}
	j.Close(false)

	if _, err := os.Stat(b); !os.IsNotExist(err) {
		t.Fatal("victim should be missing while staged")
	}
	reports, err := dedupRecover(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 || len(reports[0].Restored) != 1 {
		t.Fatalf("unexpected reports: %+v", reports)
	}
	if got, _ := os.ReadFile(b); string(got) != string(content) {
		t.Fatal("victim content not restored")
	}
	if inodeOf(t, a) == inodeOf(t, b) {
		t.Fatal("restored victim must keep an independent inode")
	}
}

// ---- journal durability --------------------------------------------------

func TestDedupJournalRoundTrip(t *testing.T) {
	root := t.TempDir()
	j := newTestJournal(t, root)
	if err := j.Log(dedupRecord{Type: recMergeBegin, Seq: 7, GID: 3, Strategy: "hardlink"}); err != nil {
		t.Fatal(err)
	}
	path := j.f.Name()
	j.Close(false)

	recs, err := readJournalFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 { // job.begin + merge.begin + job.end
		t.Fatalf("want 3 records, got %d", len(recs))
	}
	if recs[1].Type != recMergeBegin || recs[1].Seq != 7 || recs[1].Job == "" {
		t.Fatalf("record round-trip wrong: %+v", recs[1])
	}
	if recs[2].Type != recJobEnd {
		t.Fatalf("last record want %s, got %s", recJobEnd, recs[2].Type)
	}
}

func TestDedupHumanSize(t *testing.T) {
	cases := map[int64]string{0: "0B", 1023: "1023B", 1024: "1.0KiB", 1536: "1.5KiB"}
	for in, want := range cases {
		if got := dedupHumanSize(in); got != want {
			t.Errorf("dedupHumanSize(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestDedupKeepStrategyIsNoop(t *testing.T) {
	root := t.TempDir()
	content := []byte("keep me independent please padding padding")
	a, b := makePair(t, root, "a", "b", content, time.Time{})
	groups := scanGroups(t, root)
	g := findGroupByHash(groups, hashHex(content))
	j := newTestJournal(t, root)
	mg := newDedupMerger(j)
	res, err := mg.merge(g, 0, dedupKeep)
	if err != nil || res != nil {
		t.Fatalf("keep must be a no-op, got res=%v err=%v", res, err)
	}
	if inodeOf(t, a) == inodeOf(t, b) {
		t.Fatal("keep must not link files")
	}
	j.Close(false)
}

func Example_dedupDur() {
	fmt.Println(dedupDur(90 * time.Second))
	// Output: 1m30s
}
