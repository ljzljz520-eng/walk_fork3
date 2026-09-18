package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Journal layout under <root>/.walk-dedup:
//
//	journal-<job>.jsonl          append-only, fsync'ed JSON lines
//	recovery/<job>/<seq>-...     staged (recoverable) victim copies
//	cas/ab/cd/<sha256>           content-addressed store (cas strategy)
//
// A staged victim is kept until its replacement has been verified. Recovery
// copies of committed merges survive until the dedup session ends; an
// interrupted process is reconciled by dedupRecover on the next launch.

const (
	recJobBegin      = "job.begin"
	recScanStats     = "scan.stats"
	recMergeBegin    = "merge.begin"
	recVictimStage   = "victim.stage"
	recVictimReplace = "victim.replace"
	recVictimVerify  = "victim.verify"
	recMergeCommit   = "merge.commit"
	recMergeRollback = "merge.rollback"
	recMergeUndo     = "merge.undo"
	recRecoveryPurge = "recovery.purge"
	recRecoverRun    = "recover.run"
	recJobEnd        = "job.end"
	recJobAbort      = "job.abort"
)

type dedupRecord struct {
	TS       time.Time `json:"ts"`
	Job      string    `json:"job"`
	Type     string    `json:"type"`
	Seq      int       `json:"seq,omitempty"`
	GID      int       `json:"gid,omitempty"`
	Size     int64     `json:"size,omitempty"`
	Hash     string    `json:"hash,omitempty"`
	Strategy string    `json:"strategy,omitempty"`
	Survivor string    `json:"survivor,omitempty"`
	Path     string    `json:"path,omitempty"`
	Recovery string    `json:"recovery,omitempty"`
	Dev      uint64    `json:"dev,omitempty"`
	Ino      uint64    `json:"ino,omitempty"`
	OK       *bool     `json:"ok,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	Paths    []string  `json:"paths,omitempty"`
	Warnings []string  `json:"warnings,omitempty"`
	Root     string    `json:"root,omitempty"`
	Walked   int64     `json:"walked,omitempty"`
	Groups   int       `json:"groups,omitempty"`
}

type dedupJournal struct {
	mu       sync.Mutex
	f        *os.File
	Root     string
	Job      string
	dir      string // <root>/.walk-dedup
	recovery string // <root>/.walk-dedup/recovery/<job>
	cas      string // <root>/.walk-dedup/cas
	records  []dedupRecord
}

func dedupDir(root string) string {
	return filepath.Join(root, dedupDirName)
}

func newDedupJournal(root string) (*dedupJournal, error) {
	dir := dedupDir(root)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	var b [4]byte
	_, _ = rand.Read(b[:])
	job := time.Now().Format("20060102-150405.000000") + "-" + hex.EncodeToString(b[:])
	f, err := os.OpenFile(filepath.Join(dir, "journal-"+job+".jsonl"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	j := &dedupJournal{
		f:        f,
		Root:     root,
		Job:      job,
		dir:      dir,
		recovery: filepath.Join(dir, "recovery", job),
		cas:      filepath.Join(dir, "cas"),
	}
	if err := j.Log(dedupRecord{Type: recJobBegin, Root: root}); err != nil {
		_ = f.Close()
		return nil, err
	}
	return j, nil
}

func (j *dedupJournal) CASDir() string { return j.cas }

// Log appends one JSON line and fsyncs so every filesystem transition is
// durable before the next one starts.
func (j *dedupJournal) Log(rec dedupRecord) error {
	rec.TS = time.Now()
	rec.Job = j.Job
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	j.mu.Lock()
	defer j.mu.Unlock()
	if _, err := j.f.Write(line); err != nil {
		return err
	}
	if err := j.f.Sync(); err != nil {
		return err
	}
	j.records = append(j.records, rec)
	return nil
}

func (j *dedupJournal) Records() []dedupRecord {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]dedupRecord, len(j.records))
	copy(out, j.records)
	return out
}

func (j *dedupJournal) Close(aborted bool) {
	typ := recJobEnd
	if aborted {
		typ = recJobAbort
	}
	_ = j.Log(dedupRecord{Type: typ})
	_ = j.f.Close()
}

// recoveryPath returns the staged-copy path for one victim of a merge seq.
func (j *dedupJournal) recoveryPath(seq int, victimPath string) (string, error) {
	if err := os.MkdirAll(j.recovery, 0o700); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(victimPath))
	name := fmt.Sprintf("%d-%s", seq, hex.EncodeToString(sum[:8]))
	return filepath.Join(j.recovery, name), nil
}

// ---------------------------------------------------------------- recovery

type dedupRecoverReport struct {
	Journal   string
	Restored  []string
	Purged    []string
	Conflicts []string
	NoChanges int
}

// dedupRecover reconcles journals left by previous (possibly crashed) runs:
// uncommitted merges are rolled back from the recovery copies; committed or
// verified victims release their recovery copies. Processed journals are
// renamed to *.done.jsonl. It is safe to run repeatedly.
func dedupRecover(root string) ([]dedupRecoverReport, error) {
	dir := dedupDir(root)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var journals []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "journal-") && strings.HasSuffix(e.Name(), ".jsonl") {
			journals = append(journals, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(journals)

	var reports []dedupRecoverReport
	for _, jp := range journals {
		recs, err := readJournalFile(jp)
		if err != nil {
			continue
		}
		rep := reconcileJournal(root, jp, recs)
		reports = append(reports, rep)
		// Mark journal as processed.
		done := strings.TrimSuffix(jp, ".jsonl") + ".done.jsonl"
		if err := os.Rename(jp, done); err != nil {
			if err := os.Remove(jp); err == nil {
				// fine
			}
		}
	}
	// Best-effort cleanup of empty recovery directories.
	_ = removeEmptyDirs(filepath.Join(dir, "recovery"))
	return reports, nil
}

func readJournalFile(path string) ([]dedupRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var recs []dedupRecord
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var rec dedupRecord
		if err := json.Unmarshal(scanner.Bytes(), &rec); err == nil {
			recs = append(recs, rec)
		}
	}
	return recs, scanner.Err()
}

type dedupStage struct {
	path     string
	recovery string
	hash     string
	verified bool
}

func reconcileJournal(root, journalPath string, recs []dedupRecord) dedupRecoverReport {
	rep := dedupRecoverReport{Journal: filepath.Base(journalPath)}

	seqs := map[int]map[string]*dedupStage{}
	var seqOrder []int
	terminal := map[int]string{} // seq -> terminal record type

	getStage := func(seq int, path string) *dedupStage {
		m := seqs[seq]
		if m == nil {
			m = map[string]*dedupStage{}
			seqs[seq] = m
			seqOrder = append(seqOrder, seq)
		}
		st := m[path]
		if st == nil {
			st = &dedupStage{path: path}
			m[path] = st
		}
		return st
	}

	for _, r := range recs {
		switch r.Type {
		case recVictimStage:
			st := getStage(r.Seq, r.Path)
			st.recovery = r.Recovery
			st.hash = r.Hash
		case recVictimVerify:
			if r.OK != nil && *r.OK {
				getStage(r.Seq, r.Path).verified = true
			}
		case recMergeCommit, recMergeRollback, recMergeUndo:
			terminal[r.Seq] = r.Type
		}
	}

	conflictDir := filepath.Join(dedupDir(root), "recovery", "conflicts")
	for _, seq := range seqOrder {
		term := terminal[seq]
		for _, st := range seqs[seq] {
			if st.recovery == "" {
				continue
			}
			_, recErr := os.Stat(st.recovery)
			if recErr != nil {
				continue // recovery copy already gone
			}
			pathOK := pathHasContent(st.path, st.hash)

			switch {
			case term == recMergeCommit || term == recMergeUndo || (term == "" && st.verified):
				// Replacement was verified or the merge was finalised.
				if pathOK {
					if err := os.Remove(st.recovery); err == nil {
						rep.Purged = append(rep.Purged, st.path)
					}
				} else {
					// Content missing/wrong: restore from recovery.
					if restoreRecovery(st, &rep) {
						// moved back, no purge
					}
				}
			case term == recMergeRollback:
				// Rollback may itself have been interrupted; finish it.
				if pathOK {
					_ = os.Remove(st.recovery)
					rep.Purged = append(rep.Purged, st.path)
				} else {
					restoreRecovery(st, &rep)
				}
			default:
				// Interrupted before commit and no verified replacement:
				// prefer the original file (its metadata), roll back.
				if pathOK && !st.verified {
					// A replacement exists but was never verified: keep it
					// aside rather than destroying either copy.
					_ = os.MkdirAll(conflictDir, 0o700)
					target := filepath.Join(conflictDir, fmt.Sprintf("seq%d-%s", seq, filepath.Base(st.recovery)))
					if err := os.Rename(st.path, target); err == nil {
						if restoreRecovery(st, &rep) {
							rep.Conflicts = append(rep.Conflicts, target)
						} else {
							_ = os.Rename(target, st.path) // undo our move
						}
					}
				} else {
					restoreRecovery(st, &rep)
				}
			}
		}
	}
	if len(rep.Restored) == 0 && len(rep.Purged) == 0 && len(rep.Conflicts) == 0 {
		rep.NoChanges = 1
	}
	return rep
}

func restoreRecovery(st *dedupStage, rep *dedupRecoverReport) bool {
	if _, err := os.Stat(st.path); err == nil {
		_ = os.Remove(st.path) // verified-correct replacement or pre-removed
	}
	if err := os.Rename(st.recovery, st.path); err != nil {
		return false
	}
	if st.hash != "" && !pathHasContent(st.path, st.hash) {
		// Restored file does not hash correctly: move it back to recovery.
		_ = os.Rename(st.path, st.recovery)
		return false
	}
	rep.Restored = append(rep.Restored, st.path)
	return true
}

// pathHasContent reports whether the regular file at path currently hashes
// to the given full content hash.
func pathHasContent(path, hash string) bool {
	if hash == "" {
		return false
	}
	f, err := dedupOpenNoFollow(path)
	if err != nil {
		return false
	}
	defer f.Close()
	id, err := dedupFStat(f)
	if err != nil || !id.Mode.IsRegular() {
		return false
	}
	h, err := dedupHashOpenFile(f, id.Size)
	if err != nil {
		return false
	}
	return h == hash
}

func removeEmptyDirs(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			_ = removeEmptyDirs(filepath.Join(dir, e.Name()))
		}
	}
	return os.Remove(dir) // only succeeds when empty
}
