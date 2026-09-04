// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package version

import "testing"

func TestShortPrefersStampedCommit(t *testing.T) {
	prev := Commit
	t.Cleanup(func() { Commit = prev })
	Commit = "abcdef0123456789"
	if got := Short(); got != "abcdef0" {
		t.Fatalf("Short() = %q", got)
	}
}

func TestLabelUsesReleaseAndShort(t *testing.T) {
	prevC, prevV := Commit, Version
	t.Cleanup(func() {
		Commit = prevC
		Version = prevV
	})
	Commit = "deadbeef"
	Version = "1.2.3"
	if got := Label(); got != "1.2.3 deadbee" {
		t.Fatalf("Label() = %q", got)
	}
	Version = ""
	if got := Label(); got != "deadbee" {
		t.Fatalf("Label() with empty Version = %q", got)
	}
}

func TestShortSHA(t *testing.T) {
	if got := shortSHA("  abc  "); got != "abc" {
		t.Fatalf("got %q", got)
	}
	if got := shortSHA(""); got != "" {
		t.Fatalf("empty got %q", got)
	}
}
