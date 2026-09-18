//go:build !linux && !darwin

package main

import (
	"errors"
	"os"
)

// Minimal fallback for platforms without x/sys/unix plumbing (Windows, ...).
// Size/hash based detection and hardlinks still work; inode, xattr, ACL and
// reflink are reported as unavailable.

func dedupIdentify(path string) (dedupIdentity, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return dedupIdentity{}, err
	}
	return dedupIdentity{
		Mode:  fi.Mode(),
		Size:  fi.Size(),
		Mtime: fi.ModTime(),
	}, nil
}

func dedupOpenNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}

func dedupFStat(f *os.File) (dedupIdentity, error) {
	fi, err := f.Stat()
	if err != nil {
		return dedupIdentity{}, err
	}
	return dedupIdentity{
		Mode:  fi.Mode(),
		Size:  fi.Size(),
		Mtime: fi.ModTime(),
	}, nil
}

func dedupPread(f *os.File, b []byte, off int64) (int, error) {
	return f.ReadAt(b, off)
}

func dedupPwrite(f *os.File, b []byte, off int64) (int, error) {
	return f.WriteAt(b, off)
}

func dedupReadXAttrSummaries(path string) map[string]dedupXAttr {
	return map[string]dedupXAttr{}
}

func dedupReadACLSummary(path string) dedupACL {
	return dedupACL{Available: false}
}

func dedupSnapshotMetadata(f *os.File) (map[string][]byte, []byte, bool, []string) {
	return map[string][]byte{}, nil, false, nil
}

func dedupApplyMetadata(dstPath string, id dedupIdentity, xattrs map[string][]byte, aclRaw []byte, aclPresent bool) []string {
	var warnings []string
	if err := os.Chmod(dstPath, id.Mode.Perm()); err != nil {
		warnings = append(warnings, err.Error())
	}
	if err := os.Chtimes(dstPath, id.Atime, id.Mtime); err != nil {
		warnings = append(warnings, err.Error())
	}
	return warnings
}

func dedupReflinkClone(src *os.File, dst string, mode os.FileMode) error {
	return errDedupReflinkUnsupported
}

func dedupSetXAttrForTest(path, name string, value []byte) error {
	return errors.New("xattr unsupported on this platform")
}
