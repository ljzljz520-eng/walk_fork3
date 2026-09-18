package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Safe merge semantics.
//
// For one duplicate group with a chosen survivor:
//
//  1. Open EVERY member O_RDONLY|O_NOFOLLOW, fstat each descriptor and
//     re-hash the full content from the descriptors. Abort if inode/size or
//     hash no longer matches the scan results (TOCTOU protection).
//  2. For CAS: materialise and verify the content-addressed object before
//     touching any member path.
//  3. For every victim path: snapshot its metadata (xattr/ACL/times), rename
//     it into the per-job recovery directory (journal victim.stage), create
//     the replacement (hardlink / reflink clone with restored metadata /
//     link into CAS), then re-open the new path and verify inode + content
//     (journal victim.verify).
//  4. Any failure rolls back every step of the merge from the recovery
//     copies. On full success merge.commit is logged.
//
// Recovery copies are kept after commit until the dedup session ends (or an
// explicit undo), so a verified merge is still reversible; a crashed
// process is reconciled by dedupRecover on the next start.

type dedupMergeStep struct {
	Path       string
	Recovery   string
	Meta       dedupIdentity
	XAttrs     map[string][]byte
	ACL        []byte
	ACLPresent bool
	Staged     bool
	Replaced   bool
}

type dedupMergeResult struct {
	Seq           int
	GID           int
	Strategy      dedupStrategy
	Survivor      string
	Steps         []*dedupMergeStep
	AlreadyLinked []string
	Warnings      []string
}

type dedupMerger struct {
	j   *dedupJournal
	seq int
}

func newDedupMerger(j *dedupJournal) *dedupMerger {
	return &dedupMerger{j: j}
}

type dedupOpenMember struct {
	meta *dedupMeta
	f    *os.File
	id   dedupIdentity
}

func (mg *dedupMerger) merge(g *dedupGroup, survivorIdx int, strat dedupStrategy) (*dedupMergeResult, error) {
	if survivorIdx < 0 || survivorIdx >= len(g.Files) {
		return nil, fmt.Errorf("invalid survivor index %d", survivorIdx)
	}
	if strat == dedupKeep {
		return nil, nil
	}

	// ---- 1. open all handles and re-verify before changing anything ----
	members := make([]*dedupOpenMember, 0, len(g.Files))
	closeAll := func() {
		for _, m := range members {
			_ = m.f.Close()
		}
	}
	for _, mt := range g.Files {
		f, id, err := dedupOpenForVerify(mt)
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("open %s: %w", mt.Path, err)
		}
		h, err := dedupHashOpenFile(f, mt.Size)
		if err != nil {
			closeAll()
			return nil, fmt.Errorf("rehash %s: %w", mt.Path, err)
		}
		if h != g.Hash {
			closeAll()
			return nil, fmt.Errorf("%w: %s changed (hash mismatch)", errDedupChanged, mt.Path)
		}
		members = append(members, &dedupOpenMember{meta: mt, f: f, id: id})
	}
	defer closeAll()

	survivor := members[survivorIdx]
	survivorKey := survivor.id.key()

	res := &dedupMergeResult{
		GID:      g.ID,
		Strategy: strat,
		Survivor: survivor.meta.Path,
	}

	// Plan the list of paths that must be replaced.
	type planned struct {
		member *dedupOpenMember
		step   *dedupMergeStep
	}
	var plan []planned
	for i, m := range members {
		if i == survivorIdx {
			// The survivor itself is replaced too in CAS mode.
			if strat == dedupCAS {
				plan = append(plan, planned{m, &dedupMergeStep{Path: m.meta.Path, Meta: m.id}})
			}
			continue
		}
		if m.id.key() == survivorKey && strat != dedupCAS {
			res.AlreadyLinked = append(res.AlreadyLinked, m.meta.Path)
			continue // already a hardlink to the survivor
		}
		plan = append(plan, planned{m, &dedupMergeStep{Path: m.meta.Path, Meta: m.id}})
	}
	if len(plan) == 0 {
		return res, nil
	}

	// ---- 2. CAS object exists and is verified before any staging ----
	casObject := ""
	if strat == dedupCAS {
		obj, err := mg.ensureCASObject(g, survivor.f)
		if err != nil {
			return nil, fmt.Errorf("cas object: %w", err)
		}
		casObject = obj
	}

	mg.seq++
	res.Seq = mg.seq

	if err := mg.j.Log(dedupRecord{
		Type: recMergeBegin, Seq: mg.seq, GID: g.ID, Size: g.Size, Hash: g.Hash,
		Strategy: strat.String(), Survivor: survivor.meta.Path,
	}); err != nil {
		return nil, err
	}

	var cur *dedupMergeStep
	fail := func(msg string, args ...any) (*dedupMergeResult, error) {
		reason := fmt.Sprintf(msg, args...)
		rbWarnings := mg.rollback(g, res, cur)
		res.Warnings = append(res.Warnings, rbWarnings...)
		_ = mg.j.Log(dedupRecord{Type: recMergeRollback, Seq: mg.seq, GID: g.ID, Reason: reason, Warnings: rbWarnings})
		return res, errors.New(reason)
	}

	// ---- 3+4. stage, replace, verify, one victim at a time ----
	for _, p := range plan {
		step := p.step
		cur = step

		// Pull raw metadata off the open victim descriptor before staging.
		if strat == dedupReflink {
			xattrs, acl, aclPresent, warns := dedupSnapshotMetadata(p.member.f)
			step.XAttrs = xattrs
			step.ACL = acl
			step.ACLPresent = aclPresent
			res.Warnings = append(res.Warnings, warns...)
		}

		recovery, err := mg.j.recoveryPath(mg.seq, step.Path)
		if err != nil {
			return fail("recovery path for %s: %v", step.Path, err)
		}
		step.Recovery = recovery
		if err := stageToRecovery(step.Path, recovery, g.Hash); err != nil {
			return fail("stage %s: %v", step.Path, err)
		}
		step.Staged = true
		if err := mg.j.Log(dedupRecord{
			Type: recVictimStage, Seq: mg.seq, GID: g.ID,
			Path: step.Path, Recovery: recovery, Hash: g.Hash,
			Dev: step.Meta.Dev, Ino: step.Meta.Ino,
		}); err != nil {
			return fail("journal stage %s: %v", step.Path, err)
		}

		var replaceErr error
		switch strat {
		case dedupHardlink:
			replaceErr = os.Link(survivor.meta.Path, step.Path)
		case dedupCAS:
			replaceErr = os.Link(casObject, step.Path)
		case dedupReflink:
			replaceErr = dedupReflinkClone(survivor.f, step.Path, step.Meta.Mode)
			if replaceErr == nil {
				res.Warnings = append(res.Warnings,
					dedupApplyMetadata(step.Path, step.Meta, step.XAttrs, step.ACL, step.ACLPresent)...)
			}
		}
		if replaceErr != nil {
			return fail("replace %s via %s: %v", step.Path, strat, replaceErr)
		}
		step.Replaced = true
		if err := mg.j.Log(dedupRecord{
			Type: recVictimReplace, Seq: mg.seq, GID: g.ID,
			Path: step.Path, Strategy: strat.String(),
		}); err != nil {
			return fail("journal replace %s: %v", step.Path, err)
		}

		ok, verifyMsg := mg.verifyReplacement(step, g, strat, survivor.id, casObject)
		vrec := dedupRecord{
			Type: recVictimVerify, Seq: mg.seq, GID: g.ID,
			Path: step.Path, Hash: g.Hash,
		}
		if ok {
			b := true
			vrec.OK = &b
			_ = mg.j.Log(vrec)
		} else {
			b := false
			vrec.OK = &b
			vrec.Reason = verifyMsg
			_ = mg.j.Log(vrec)
			return fail("verify %s: %s", step.Path, verifyMsg)
		}
		res.Steps = append(res.Steps, step)
	}

	if err := mg.j.Log(dedupRecord{Type: recMergeCommit, Seq: mg.seq, GID: g.ID}); err != nil {
		return nil, err
	}
	return res, nil
}

// verifyReplacement re-opens the new path and checks content hash and inode
// expectations (linked to survivor/CAS object; distinct inode for reflink).
func (mg *dedupMerger) verifyReplacement(step *dedupMergeStep, g *dedupGroup, strat dedupStrategy, survivorID dedupIdentity, casObject string) (bool, string) {
	f, err := dedupOpenNoFollow(step.Path)
	if err != nil {
		return false, "open replacement: " + err.Error()
	}
	defer f.Close()
	id, err := dedupFStat(f)
	if err != nil {
		return false, "stat replacement: " + err.Error()
	}
	if !id.Mode.IsRegular() {
		return false, "replacement is not a regular file"
	}
	h, err := dedupHashOpenFile(f, g.Size)
	if err != nil {
		return false, "hash replacement: " + err.Error()
	}
	if h != g.Hash {
		return false, "content hash mismatch"
	}
	switch strat {
	case dedupHardlink:
		if id.key() != survivorID.key() {
			return false, "not linked to survivor"
		}
	case dedupCAS:
		objID, err := dedupIdentify(casObject)
		if err != nil {
			return false, "stat cas object: " + err.Error()
		}
		if id.key() != objID.key() {
			return false, "not linked to cas object"
		}
	case dedupReflink:
		if id.key() == survivorID.key() {
			return false, "reflink shares inode with survivor (not a clone)"
		}
	}
	return true, ""
}

// rollback restores every staged step from its recovery copy, newest first.
// The replacement path is removed only after the recovery copy is proven to
// contain the right content.
func (mg *dedupMerger) rollback(g *dedupGroup, res *dedupMergeResult, cur *dedupMergeStep) []string {
	var warnings []string
	steps := make([]*dedupMergeStep, 0, len(res.Steps)+1)
	steps = append(steps, res.Steps...)
	if cur != nil && cur.Staged {
		// The in-flight step is not yet part of res.Steps.
		known := false
		for _, s := range steps {
			if s == cur {
				known = true
			}
		}
		if !known {
			steps = append(steps, cur)
		}
	}
	for i := len(steps) - 1; i >= 0; i-- {
		step := steps[i]
		if !step.Staged {
			continue
		}
		if _, err := os.Stat(step.Recovery); err != nil {
			warnings = append(warnings, fmt.Sprintf("recovery copy missing for %s", step.Path))
			continue
		}
		if !pathHasContent(step.Recovery, g.Hash) {
			warnings = append(warnings, fmt.Sprintf("recovery copy corrupt for %s; left in place", step.Path))
			continue
		}
		if _, err := os.Lstat(step.Path); err == nil {
			if err := os.Remove(step.Path); err != nil {
				warnings = append(warnings, fmt.Sprintf("unlink replacement %s: %v", step.Path, err))
				continue
			}
		}
		if err := os.Rename(step.Recovery, step.Path); err != nil {
			warnings = append(warnings, fmt.Sprintf("restore %s: %v", step.Path, err))
			continue
		}
		step.Staged = false
		step.Replaced = false
	}
	return warnings
}

// undo restores the original independent copies from the retained recovery
// copies and logs merge.undo. CAS objects are left in the store for reuse.
func (mg *dedupMerger) undo(g *dedupGroup, res *dedupMergeResult) ([]string, error) {
	var warnings []string
	for i := len(res.Steps) - 1; i >= 0; i-- {
		step := res.Steps[i]
		if _, err := os.Stat(step.Recovery); err != nil {
			warnings = append(warnings, fmt.Sprintf("recovery copy missing for %s", step.Path))
			continue
		}
		if !pathHasContent(step.Recovery, g.Hash) {
			warnings = append(warnings, fmt.Sprintf("recovery copy corrupt for %s", step.Path))
			continue
		}
		if _, err := os.Lstat(step.Path); err == nil {
			if err := os.Remove(step.Path); err != nil {
				warnings = append(warnings, fmt.Sprintf("unlink %s: %v", step.Path, err))
				continue
			}
		}
		if err := os.Rename(step.Recovery, step.Path); err != nil {
			warnings = append(warnings, fmt.Sprintf("restore %s: %v", step.Path, err))
			continue
		}
	}
	if err := mg.j.Log(dedupRecord{
		Type: recMergeUndo, Seq: res.Seq, GID: g.ID, Reason: "user undo", Warnings: warnings,
	}); err != nil {
		return warnings, err
	}
	return warnings, nil
}

// purgeRecovery deletes retained recovery copies of a finished (committed or
// undone) merge. It is only called after the post-replace verification.
func (mg *dedupMerger) purgeRecovery(res *dedupMergeResult) []string {
	var purged, missing []string
	for _, step := range res.Steps {
		if step.Recovery == "" {
			continue
		}
		if _, err := os.Stat(step.Recovery); err == nil {
			if err := os.Remove(step.Recovery); err == nil {
				purged = append(purged, step.Recovery)
			}
		} else {
			missing = append(missing, step.Recovery)
		}
	}
	if len(purged) > 0 {
		_ = mg.j.Log(dedupRecord{Type: recRecoveryPurge, Seq: res.Seq, GID: res.GID, Paths: purged})
	}
	return missing
}

// stageToRecovery moves the victim out of the way. On the same filesystem
// this is an atomic rename; cross-device it falls back to a verified copy.
func stageToRecovery(path, recovery, hash string) error {
	if err := os.Rename(path, recovery); err == nil {
		return nil
	}
	if err := copyRegular(path, recovery); err != nil {
		return err
	}
	if !pathHasContent(recovery, hash) {
		_ = os.Remove(recovery)
		return fmt.Errorf("%w: staged copy of %s does not hash correctly", errDedupVerify, path)
	}
	return os.Remove(path)
}

func copyRegular(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, fi.Mode().Perm())
	if err != nil {
		return err
	}
	buf := make([]byte, dedupIOBufSize)
	for {
		n, rerr := in.Read(buf)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				_ = out.Close()
				_ = os.Remove(dst)
				return werr
			}
		}
		if rerr != nil {
			_ = out.Close()
			if errors.Is(rerr, io.EOF) {
				return nil
			}
			_ = os.Remove(dst)
			return rerr
		}
	}
}

// ensureCASObject materialises <cas>/ab/cd/<sha256> from the survivor
// descriptor and verifies it. Existing objects are verified and reused.
func (mg *dedupMerger) ensureCASObject(g *dedupGroup, src *os.File) (string, error) {
	dir := filepath.Join(mg.j.CASDir(), g.Hash[0:2], g.Hash[2:4])
	obj := filepath.Join(dir, g.Hash)
	if _, err := os.Stat(obj); err == nil {
		if !pathHasContent(obj, g.Hash) {
			return "", fmt.Errorf("%w: existing cas object %s", errDedupVerify, obj)
		}
		return obj, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	tmp := fmt.Sprintf("%s.tmp-%s-%d", obj, mg.j.Job, mg.seq+1)
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	copyErr := error(nil)
	buf := make([]byte, dedupIOBufSize)
	var off int64
	for off < g.Size {
		nr := len(buf)
		if int64(nr) > g.Size-off {
			nr = int(g.Size - off)
		}
		n, err := dedupPread(src, buf[:nr], off)
		if n > 0 {
			if _, werr := out.Write(buf[:n]); werr != nil {
				copyErr = werr
				break
			}
			off += int64(n)
		}
		if err != nil {
			copyErr = err
			break
		}
		if n == 0 {
			break
		}
	}
	if copyErr == nil {
		copyErr = out.Sync()
	}
	_ = out.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return "", copyErr
	}
	if err := os.Chmod(tmp, 0o444); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, obj); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if !pathHasContent(obj, g.Hash) {
		return "", fmt.Errorf("%w: cas object %s", errDedupVerify, obj)
	}
	return obj, nil
}
