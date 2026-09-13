// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package logging

import (
	"strings"
	"testing"
)

func TestSafe(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"clean", "connector-abc123", "connector-abc123"},
		{"newline forged line", "a\nINFO forged", "a INFO forged"},
		{"crlf", "x\r\ny", "x  y"},
		{"tab", "a\tb", "a b"},
		{"escape seq", "\x1b[31mred", " [31mred"},
		{"del", "a\x7fb", "a b"},
		{"unicode kept", "caf\u00e9", "caf\u00e9"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Safe(tt.in); got != tt.want {
				t.Fatalf("Safe(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSafeNoControlBytes(t *testing.T) {
	in := "line1\nline2\x00\x1f\x7fend"
	got := Safe(in)
	for _, r := range got {
		if r < 0x20 || r == 0x7f {
			t.Fatalf("Safe(%q) still contains control rune %U", in, r)
		}
	}
	if !strings.HasSuffix(got, "end") {
		t.Fatalf("Safe(%q) = %q, want suffix preserved", in, got)
	}
}
