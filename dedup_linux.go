//go:build linux

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

const posixACLAttr = "system.posix_acl_access"

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
		Dev: st.Dev, Ino: st.Ino, Nlink: uint64(st.Nlink),
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

// dedupReadXAttrSummaries lists xattrs and hashes their values without
// retaining the values themselves.
func dedupReadXAttrSummaries(path string) map[string]dedupXAttr {
	out := map[string]dedupXAttr{}
	size, err := unix.Listxattr(path, nil)
	if err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
			return out
		}
		return out
	}
	if size == 0 {
		return out
	}
	buf := make([]byte, size)
	if _, err := unix.Listxattr(path, buf); err != nil {
		return out
	}
	for _, name := range splitNullNames(buf) {
		sz, err := unix.Getxattr(path, name, nil)
		xa := dedupXAttr{}
		switch {
		case err != nil:
			xa.Err = err.Error()
		case sz > dedupMaxXAttr:
			xa.Size = sz
			xa.Err = "xattr value too large"
		default:
			value := make([]byte, sz)
			n, err := unix.Getxattr(path, name, value)
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
	acl := dedupACL{Available: true}
	size, err := unix.Getxattr(path, posixACLAttr, nil)
	if err != nil {
		return acl // ENODATA: no extended ACL beyond the mode bits
	}
	raw := make([]byte, size)
	n, err := unix.Getxattr(path, posixACLAttr, raw)
	if err != nil {
		acl.Err = err.Error()
		return acl
	}
	raw = raw[:n]
	acl.Present = true
	acl.Entries = parsePosixACLEntries(raw)
	sum := sha256.Sum256(raw)
	acl.Hash = hex.EncodeToString(sum[:])
	return acl
}

// parsePosixACLEntries parses struct posix_acl_xattr: 4-byte little-endian
// header followed by 8-byte entries (le16 tag, le16 perm, le32 id).
func parsePosixACLEntries(raw []byte) int {
	if len(raw) < 4 {
		return 0
	}
	return (len(raw) - 4) / 8
}

// dedupSnapshotMetadata pulls raw xattrs and the raw POSIX ACL from an open
// descriptor right before a victim is staged, so a reflink clone can be
// restored to carry the victim's original metadata.
func dedupSnapshotMetadata(f *os.File) (map[string][]byte, []byte, bool, []string) {
	warnings := []string{}
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

	var aclRaw []byte
	aclPresent := false
	if sz, err := unix.Fgetxattr(fd, posixACLAttr, nil); err == nil && sz > 0 {
		aclRaw = make([]byte, sz)
		if n, err := unix.Fgetxattr(fd, posixACLAttr, aclRaw); err == nil {
			aclRaw = aclRaw[:n]
			aclPresent = true
		} else {
			warnings = append(warnings, fmt.Sprintf("acl: %v", err))
		}
	}
	return xattrs, aclRaw, aclPresent, warnings
}

// dedupApplyMetadata restores victim metadata onto a freshly created clone.
// Every step is best-effort: failures are collected, never fatal (the
// content replacement has already been verified).
func dedupApplyMetadata(dstPath string, id dedupIdentity, xattrs map[string][]byte, aclRaw []byte, aclPresent bool) []string {
	var warnings []string

	if err := os.Chmod(dstPath, id.Mode.Perm()); err != nil {
		warnings = append(warnings, fmt.Sprintf("chmod: %v", err))
	}
	if err := os.Chown(dstPath, int(id.Uid), int(id.Gid)); err != nil {
		warnings = append(warnings, fmt.Sprintf("chown: %v", err))
	}
	if err := os.Chtimes(dstPath, id.Atime, id.Mtime); err != nil {
		warnings = append(warnings, fmt.Sprintf("utimens: %v", err))
	}
	for name, value := range xattrs {
		if err := unix.Setxattr(dstPath, name, value, 0); err != nil {
			warnings = append(warnings, fmt.Sprintf("setxattr %s: %v", name, err))
		}
	}
	if aclPresent {
		if err := unix.Setxattr(dstPath, posixACLAttr, aclRaw, 0); err != nil {
			warnings = append(warnings, fmt.Sprintf("set acl: %v", err))
		}
	}
	return warnings
}

func dedupReflinkClone(src *os.File, dst string, mode os.FileMode) error {
	fd, err := unix.Open(dst, unix.O_CREAT|unix.O_WRONLY|unix.O_EXCL|unix.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return err
	}
	cloneErr := unix.IoctlFileClone(fd, int(src.Fd()))
	if cloneErr != nil {
		_ = unix.Close(fd)
		_ = unix.Unlink(dst)
		switch {
		case errors.Is(cloneErr, unix.EOPNOTSUPP), errors.Is(cloneErr, unix.ENOTSUP),
			errors.Is(cloneErr, unix.EXDEV), errors.Is(cloneErr, unix.ENOSYS):
			return fmt.Errorf("%w: %v", errDedupReflinkUnsupported, cloneErr)
		}
		return cloneErr
	}
	if err := unix.Close(fd); err != nil {
		_ = unix.Unlink(dst)
		return err
	}
	return nil
}

func dedupSetXAttrForTest(path, name string, value []byte) error {
	return unix.Setxattr(path, name, value, 0)
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
