package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Duplicate-file detection and safe merging.
//
// Pipeline:
//
//  1. Walk a directory tree (regular files only, one filesystem) and bucket
//     candidates by size.
//  2. Inside every size bucket with >1 file, compute a cheap "quick hash"
//     (prefix + suffix samples; whole content for small files).
//  3. Inside every surviving quick-hash bucket, compute the full SHA-256.
//
// The resulting groups are enriched with inode, sparseness, xattr/ACL and
// mtime metadata so the user can see that identical *content* may live in
// files with different metadata. Merging is implemented in dedup_merge.go
// with open-handle re-verification, journaling and recovery copies.

const (
	dedupDirName   = ".walk-dedup"
	dedupQuickSize = 4 * 1024 // bytes sampled from each edge for the quick hash
	dedupIOBufSize = 1024 * 1024
	dedupMaxXAttr  = 1024 * 1024 // don't pull xattr values larger than this
)

var (
	errDedupReflinkUnsupported = errors.New("reflink is not supported on this filesystem")
	errDedupChanged            = errors.New("file changed between scan and merge")
	errDedupVerify             = errors.New("dedup verification failed")
)

type dedupStrategy int

const (
	dedupHardlink dedupStrategy = iota
	dedupReflink
	dedupCAS
	dedupKeep
)

func (s dedupStrategy) String() string {
	switch s {
	case dedupHardlink:
		return "hardlink"
	case dedupReflink:
		return "reflink"
	case dedupCAS:
		return "cas"
	default:
		return "keep"
	}
}

// dedupIdentity is the filesystem identity/stat data of a file.
type dedupIdentity struct {
	Dev, Ino, Nlink uint64
	Uid, Gid        uint32
	Mode            os.FileMode
	Size            int64
	Blocks          int64 // 512-byte blocks actually allocated
	Mtime           time.Time
	Atime           time.Time
}

type dedupIdentityKey struct{ Dev, Ino uint64 }

func (i dedupIdentity) key() dedupIdentityKey { return dedupIdentityKey{i.Dev, i.Ino} }

// dedupXAttr describes one extended attribute. Value hashes are collected
// during the scan; raw values are only pulled from open descriptors right
// before a merge.
type dedupXAttr struct {
	Size  int    `json:"size"`
	Hash  string `json:"hash"`
	Err   string `json:"err,omitempty"`
	Value []byte `json:"-"`
}

// dedupACL describes an access-control list in a portable way. On platforms
// without readable ACLs Available is false and the row is rendered as "n/a".
type dedupACL struct {
	Available bool   `json:"available"`
	Present   bool   `json:"present"`
	Entries   int    `json:"entries"`
	Hash      string `json:"hash,omitempty"`
	Err       string `json:"err,omitempty"`
	Raw       []byte `json:"-"`
}

type dedupMeta struct {
	Path   string
	Size   int64
	Dev    uint64
	Ino    uint64
	Nlink  uint64
	Mode   os.FileMode
	Uid    uint32
	Gid    uint32
	Mtime  time.Time
	Blocks int64

	XAttrs map[string]dedupXAttr
	ACL    dedupACL

	Quick         string // hex quick hash
	Hash          string // hex full sha-256
	quickComplete bool   // quick hash covered the whole file

	Err string // non-fatal collection error
}

func (m *dedupMeta) identityKey() dedupIdentityKey {
	return dedupIdentityKey{m.Dev, m.Ino}
}

// holePct reports how much of the apparent size is a hole (0 for non-sparse).
func (m *dedupMeta) holePct() float64 {
	if m.Size <= 0 || m.Blocks <= 0 {
		return 0
	}
	allocated := float64(m.Blocks) * 512
	if allocated >= float64(m.Size) {
		return 0
	}
	return (1 - allocated/float64(m.Size)) * 100
}

type dedupGroup struct {
	ID    int
	Size  int64
	Hash  string
	Files []*dedupMeta
}

// distinctInodes counts physical inodes in the group. Paths already pointing
// at the same inode are the same file, not mergeable duplicates.
func (g *dedupGroup) distinctInodes() int {
	seen := map[dedupIdentityKey]bool{}
	for _, f := range g.Files {
		seen[f.identityKey()] = true
	}
	return len(seen)
}

func (g *dedupGroup) alreadyLinked(idx int) bool {
	if idx < 0 || idx >= len(g.Files) {
		return false
	}
	sur := g.Files[idx]
	for i, f := range g.Files {
		if i != idx && f.identityKey() == sur.identityKey() {
			return true
		}
	}
	return false
}

// isLinkedWithSurvivor reports whether the row shares an inode with the
// chosen survivor row (i.e. merging would be a no-op).
func (g *dedupGroup) isLinkedWithSurvivor(row, survivor int) bool {
	if row == survivor || row < 0 || survivor < 0 || row >= len(g.Files) || survivor >= len(g.Files) {
		return false
	}
	return g.Files[row].identityKey() == g.Files[survivor].identityKey()
}

type dedupStats struct {
	Walked     int64
	GroupCount int64
	FileCount  int64
	Wasted     int64 // bytes reclaimable, counting distinct inodes
}

type dedupProgressView struct {
	Phase   string
	Walked  int64
	Hashing int64
	Buckets int
	Groups  int
	Current string
}

type dedupProgress struct {
	mu      sync.Mutex
	phase   string
	walked  int64
	hashing int64
	buckets int
	groups  int
	current string
}

func (p *dedupProgress) set(phase string) {
	p.mu.Lock()
	p.phase = phase
	p.mu.Unlock()
}

func (p *dedupProgress) addWalked(path string) {
	p.mu.Lock()
	p.walked++
	p.current = path
	p.mu.Unlock()
}

func (p *dedupProgress) setBuckets(n int) {
	p.mu.Lock()
	p.buckets = n
	p.mu.Unlock()
}

func (p *dedupProgress) addHashed() {
	p.mu.Lock()
	p.hashing++
	p.mu.Unlock()
}

func (p *dedupProgress) setGroups(n int) {
	p.mu.Lock()
	p.groups = n
	p.mu.Unlock()
}

func (p *dedupProgress) view() dedupProgressView {
	p.mu.Lock()
	defer p.mu.Unlock()
	return dedupProgressView{
		Phase: p.phase, Walked: p.walked, Hashing: p.hashing,
		Buckets: p.buckets, Groups: p.groups, Current: p.current,
	}
}

// dedupScanTree runs the whole 3-phase detection.
func dedupScanTree(root string, ctx context.Context, prog *dedupProgress) ([]*dedupGroup, dedupStats, error) {
	var stats dedupStats

	rootID, err := dedupIdentify(root)
	if err != nil {
		return nil, stats, fmt.Errorf("stat scan root: %w", err)
	}

	// Phase 1: walk + size buckets.
	prog.set("scan sizes")
	buckets := map[int64][]*dedupMeta{}
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return nil // skip unreadable entries, keep going
		}
		if d.IsDir() {
			if path != root {
				// Stay on the root filesystem (find -xdev behaviour).
				if id, e := dedupIdentify(path); e == nil && id.Dev != rootID.Dev {
					return filepath.SkipDir
				}
			}
			// Never scan our own journal/recovery/cas directory.
			if d.Name() == dedupDirName && filepath.Dir(path) == root {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 || !d.Type().IsRegular() {
			return nil
		}
		id, err := dedupIdentify(path)
		if err != nil {
			return nil
		}
		prog.addWalked(path)
		buckets[id.Size] = append(buckets[id.Size], &dedupMeta{
			Path: path, Size: id.Size, Dev: id.Dev, Ino: id.Ino, Nlink: id.Nlink,
			Mode: id.Mode, Uid: id.Uid, Gid: id.Gid, Mtime: id.Mtime, Blocks: id.Blocks,
		})
		return nil
	})
	if walkErr != nil {
		return nil, stats, walkErr
	}
	stats.Walked = prog.view().Walked

	candidates := 0
	for _, ms := range buckets {
		if len(ms) > 1 {
			candidates += len(ms)
		}
	}
	prog.setBuckets(candidates)

	// Phases 2+3: quick hash then full hash.
	var groups []*dedupGroup
	for size, metas := range buckets {
		if err := ctx.Err(); err != nil {
			return nil, stats, err
		}
		if len(metas) < 2 {
			continue
		}
		prog.set("quick hash")

		quick := map[string][]*dedupMeta{}
		for _, mt := range metas {
			if err := ctx.Err(); err != nil {
				return nil, stats, err
			}
			qh, complete, err := dedupQuickHashFile(mt)
			prog.addHashed()
			if err != nil {
				mt.Err = err.Error()
				continue
			}
			mt.Quick = qh
			mt.quickComplete = complete
			quick[qh] = append(quick[qh], mt)
		}

		for _, qs := range quick {
			if len(qs) < 2 {
				continue
			}
			prog.set("full hash")
			full := map[string][]*dedupMeta{}
			for _, mt := range qs {
				if mt.quickComplete {
					// Quick hash covered the entire content; it is the full hash.
					mt.Hash = mt.Quick
				} else {
					if err := ctx.Err(); err != nil {
						return nil, stats, err
					}
					h, err := dedupFullHashFile(mt)
					prog.addHashed()
					if err != nil {
						mt.Err = err.Error()
						continue
					}
					mt.Hash = h
				}
				full[mt.Hash] = append(full[mt.Hash], mt)
			}
			for h, hs := range full {
				if len(hs) < 2 {
					continue
				}
				groups = append(groups, &dedupGroup{Size: size, Hash: h, Files: hs})
			}
		}
	}

	// Enrich groups with metadata needed for the diff display.
	prog.set("read metadata")
	for _, g := range groups {
		for _, mt := range g.Files {
			if err := ctx.Err(); err != nil {
				return nil, stats, err
			}
			mt.XAttrs = dedupReadXAttrSummaries(mt.Path)
			mt.ACL = dedupReadACLSummary(mt.Path)
		}
		sort.Slice(g.Files, func(i, j int) bool { return g.Files[i].Path < g.Files[j].Path })
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Size != groups[j].Size {
			return groups[i].Size > groups[j].Size
		}
		return groups[i].Hash < groups[j].Hash
	})
	for i := range groups {
		groups[i].ID = i
	}
	prog.setGroups(len(groups))

	for _, g := range groups {
		stats.GroupCount++
		stats.FileCount += int64(len(g.Files))
		stats.Wasted += g.Size * int64(g.distinctInodes()-1)
	}
	prog.set("done")
	return groups, stats, nil
}

// dedupHashRanges hashes the given [start,end) byte ranges of an open file.
func dedupHashRanges(f *os.File, ranges ...[2]int64) (string, error) {
	h := sha256.New()
	buf := make([]byte, dedupIOBufSize)
	for _, r := range ranges {
		off, end := r[0], r[1]
		for off < end {
			nr := len(buf)
			if int64(nr) > end-off {
				nr = int(end - off)
			}
			n, err := dedupPread(f, buf[:nr], off)
			if n > 0 {
				h.Write(buf[:n])
				off += int64(n)
			}
			if err != nil && !errors.Is(err, io.EOF) {
				return "", err
			}
			if n == 0 {
				break
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// dedupOpenForVerify opens the file without following symlinks and confirms
// it is still the same inode/size that was scanned.
func dedupOpenForVerify(m *dedupMeta) (*os.File, dedupIdentity, error) {
	f, err := dedupOpenNoFollow(m.Path)
	if err != nil {
		return nil, dedupIdentity{}, err
	}
	id, err := dedupFStat(f)
	if err != nil {
		_ = f.Close()
		return nil, dedupIdentity{}, err
	}
	if id.Dev != m.Dev || id.Ino != m.Ino || id.Size != m.Size {
		_ = f.Close()
		return nil, id, fmt.Errorf("%w: %s", errDedupChanged, m.Path)
	}
	return f, id, nil
}

func dedupQuickHashFile(m *dedupMeta) (hash string, complete bool, err error) {
	f, _, err := dedupOpenForVerify(m)
	if err != nil {
		return "", false, err
	}
	defer f.Close()

	if m.Size <= 2*dedupQuickSize {
		h, err := dedupHashRanges(f, [2]int64{0, m.Size})
		return h, true, err
	}
	h, err := dedupHashRanges(f,
		[2]int64{0, dedupQuickSize},
		[2]int64{m.Size - dedupQuickSize, m.Size},
	)
	return h, false, err
}

func dedupFullHashFile(m *dedupMeta) (string, error) {
	f, _, err := dedupOpenForVerify(m)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return dedupHashRanges(f, [2]int64{0, m.Size})
}

func dedupHashOpenFile(f *os.File, size int64) (string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		// pread does not depend on the offset, but keep best effort.
	}
	return dedupHashRanges(f, [2]int64{0, size})
}

// dedupXAttrDiff compares xattr sets: names only on one side and names whose
// value hashes differ.
func dedupXAttrDiff(a, b map[string]dedupXAttr) (onlyA, onlyB, changed []string) {
	for name, xa := range a {
		xb, ok := b[name]
		switch {
		case !ok:
			onlyA = append(onlyA, name)
		case xa.Hash != xb.Hash:
			changed = append(changed, name)
		}
	}
	for name := range b {
		if _, ok := a[name]; !ok {
			onlyB = append(onlyB, name)
		}
	}
	sort.Strings(onlyA)
	sort.Strings(onlyB)
	sort.Strings(changed)
	return
}

func dedupModeString(mode os.FileMode) string {
	result := make([]byte, 10)
	switch {
	case mode&os.ModeDir != 0:
		result[0] = 'd'
	case mode&os.ModeSymlink != 0:
		result[0] = 'l'
	case mode&os.ModeSocket != 0:
		result[0] = 's'
	case mode&os.ModeNamedPipe != 0:
		result[0] = 'p'
	case mode&os.ModeCharDevice != 0:
		result[0] = 'c'
	case mode&os.ModeDevice != 0:
		result[0] = 'b'
	default:
		result[0] = '-'
	}
	const rwx = "rwxrwxrwx"
	perm := uint32(mode.Perm())
	for i := 0; i < 9; i++ {
		if perm&(1<<uint(8-i)) != 0 {
			result[i+1] = rwx[i]
		} else {
			result[i+1] = '-'
		}
	}
	if mode&os.ModeSetuid != 0 {
		result[3] = 's'
	}
	if mode&os.ModeSetgid != 0 {
		result[6] = 's'
	}
	if mode&os.ModeSticky != 0 {
		result[9] = 't'
	}
	return string(result)
}

func dedupFmtTime(t time.Time) string {
	if t.Year() == time.Now().Year() {
		return t.Format("Jan 2 15:04")
	}
	return t.Format("Jan 2 2006")
}

func dedupHumanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
