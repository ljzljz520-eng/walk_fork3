//go:build darwin

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// On macOS NFSv4/ACL data is only exposed through libc acl_* calls, which are
// not wrapped by x/sys and would require cgo. We report ACLs as unavailable
// (content identity still relies on hashes; xattrs are fully supported).

func dedupIdentify(path string) (dedupIdentity, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return dedupIdentity{}, err
	}
	return statToIdentity(st), nil
}

func dedupOpenNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func dedupFStat(f *os.File) (dedupIdentity, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return dedupIdentity{}, err
	}
	return statToIdentity(st), nil
}

func statToIdentity(st unix.Stat_t) dedupIdentity {
	return dedupIdentity{
		Dev: uint64(st.Dev), Ino: st.Ino, Nlink: uint64(st.Nlink),
		Uid: st.Uid, Gid: st.Gid,
		Mode:   os.FileMode(st.Mode),
		Size:   st.Size,
		Blocks: st.Blocks,
		Mtime:  time.Unix(st.Mtim.Sec, st.Mtim.Nsec),
		Atime:  time.Unix(st.Atim.Sec, st.Atim.Nsec),
	}
}

func dedupPread(f *os.File, b []byte, off int64) (int, error) {
	return unix.Pread(int(f.Fd()), b, off)
}

func dedupPwrite(f *os.File, b []byte, off int64) (int, error) {
	return unix.Pwrite(int(f.Fd()), b, off)
}

func dedupReadXAttrSummaries(path string) map[string]dedupXAttr {
	out := map[string]dedupXAttr{}
	size, err := unix.Llistxattr(path, nil)
	if err != nil {
		return out
	}
	if size == 0 {
		return out
	}
	buf := make([]byte, size)
	if _, err := unix.Llistxattr(path, buf); err != nil {
		return out
	}
	for _, name := range splitNullNames(buf) {
		sz, err := unix.Lgetxattr(path, name, nil)
		xa := dedupXAttr{}
		switch {
		case err != nil:
			xa.Err = err.Error()
		case sz > dedupMaxXAttr:
			xa.Size = sz
			xa.Err = "xattr value too large"
		default:
			value := make([]byte, sz)
			n, err := unix.Lgetxattr(path, name, value)
			if err != nil {
				xa.Err = err.Error()
			} else {
				value = value[:n]
				xa.Size = n
				sum := sha256.Sum256(value)
				xa.Hash = hex.EncodeToString(sum[:])
			}
		}
		out[name] = xa
	}
	return out
}

func dedupReadACLSummary(path string) dedupACL {
	return dedupACL{Available: false}
}

func dedupSnapshotMetadata(f *os.File) (map[string][]byte, []byte, bool, []string) {
	var warnings []string
	fd := int(f.Fd())
	xattrs := map[string][]byte{}

	size, err := unix.Flistxattr(fd, nil)
	if err == nil && size > 0 {
		buf := make([]byte, size)
		if n, err := unix.Flistxattr(fd, buf); err == nil {
			buf = buf[:n]
			for _, name := range splitNullNames(buf) {
				sz, err := unix.Fgetxattr(fd, name, nil)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("xattr %s: %v", name, err))
					continue
				}
				if sz > dedupMaxXAttr {
					warnings = append(warnings, fmt.Sprintf("xattr %s too large (%d), dropped", name, sz))
					continue
				}
				value := make([]byte, sz)
				n, err := unix.Fgetxattr(fd, name, value)
				if err != nil {
					warnings = append(warnings, fmt.Sprintf("xattr %s: %v", name, err))
					continue
				}
				xattrs[name] = value[:n]
			}
		}
	}
	return xattrs, nil, false, warnings
}

func dedupApplyMetadata(dstPath string, id dedupIdentity, xattrs map[string][]byte, aclRaw []byte, aclPresent bool) []string {
	var warnings []string

	if err := os.Chmod(dstPath, id.Mode.Perm()); err != nil {
		warnings = append(warnings, fmt.Sprintf("chmod: %v", err))
	}
	if err := os.Chown(dstPath, int(id.Uid), int(id.Gid)); err != nil {
		warnings = append(warnings, fmt.Sprintf("chown: %v", err))
	}
	if err := os.Chtimes(dstPath, id.Atime, id.Mtime); err != nil {
		warnings = append(warnings, fmt.Sprintf("futimes: %v", err))
	}
	for name, value := range xattrs {
		if err := unix.Lsetxattr(dstPath, name, value, 0); err != nil {
			warnings = append(warnings, fmt.Sprintf("setxattr %s: %v", name, err))
		}
	}
	return warnings
}

func dedupReflinkClone(src *os.File, dst string, mode os.FileMode) error {
	err := unix.Clonefile(src.Name(), dst, unix.CLONE_NOFOLLOW)
	if err != nil {
		switch {
		case errors.Is(err, unix.ENOTSUP), errors.Is(err, unix.EOPNOTSUPP),
			errors.Is(err, unix.EXDEV), errors.Is(err, unix.ENOSYS):
			return fmt.Errorf("%w: %v", errDedupReflinkUnsupported, err)
		}
		return err
	}
	// clonefile creates the destination with the source mode; align it with
	// the victim mode. dedupApplyMetadata does the rest.
	if err := os.Chmod(dst, mode.Perm()); err != nil {
		_ = os.Remove(dst)
		return err
	}
	return nil
}

func dedupSetXAttrForTest(path, name string, value []byte) error {
	return unix.Lsetxattr(path, name, value, 0)
}

func splitNullNames(buf []byte) []string {
	var names []string
	start := 0
	for i, b := range buf {
		if b == 0 {
			if i > start {
				names = append(names, string(buf[start:i]))
			}
			start = i + 1
		}
	}
	if start < len(buf) {
		names = append(names, string(buf[start:]))
	}
	return names
}
