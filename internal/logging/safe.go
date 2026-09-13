// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package logging

import "strings"

// Safe returns s with ASCII control characters replaced by spaces so a
// caller-supplied value cannot forge extra log lines or inject terminal
// escape sequences into text log output.
func Safe(s string) string {
	if strings.IndexFunc(s, isUnsafeLogByte) < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			b.WriteByte(' ')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isUnsafeLogByte(r rune) bool {
	return r < 0x20 || r == 0x7f
}
