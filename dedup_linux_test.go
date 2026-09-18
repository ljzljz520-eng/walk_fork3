//go:build linux

package main

import "testing"

func TestParsePosixACLEntries(t *testing.T) {
	// 4-byte version header + two 8-byte entries.
	raw := make([]byte, 4+2*8)
	if got := parsePosixACLEntries(raw); got != 2 {
		t.Fatalf("want 2 acl entries, got %d", got)
	}
	if got := parsePosixACLEntries(raw[:3]); got != 0 {
		t.Fatalf("short header must yield 0, got %d", got)
	}
}
