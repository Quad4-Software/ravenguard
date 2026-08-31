// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package faststr

// ContainsFold reports whether substr is within s using ASCII case folding.
// substr should already be lowercase. Zero allocations.
func ContainsFold(s, substr string) bool {
	n := len(substr)
	if n == 0 {
		return true
	}
	if n > len(s) {
		return false
	}
	for i := 0; i <= len(s)-n; i++ {
		if equalFoldASCII(s[i:i+n], substr) {
			return true
		}
	}
	return false
}

// HasPrefixFold reports whether s begins with prefix using ASCII case folding.
// prefix should already be lowercase. Zero allocations.
func HasPrefixFold(s, prefix string) bool {
	n := len(prefix)
	if n > len(s) {
		return false
	}
	return equalFoldASCII(s[:n], prefix)
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca == cb {
			continue
		}
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// AppendLowerASCII appends the ASCII-lowercased form of s to dst.
func AppendLowerASCII(dst []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst = append(dst, c)
	}
	return dst
}

// ContainsBytes reports whether needle is within haystack. Zero allocations
// when needle is a string constant or already held.
func ContainsBytes(haystack []byte, needle string) bool {
	n := len(needle)
	if n == 0 {
		return true
	}
	if n > len(haystack) {
		return false
	}
	for i := 0; i <= len(haystack)-n; i++ {
		ok := true
		for j := range n {
			if haystack[i+j] != needle[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// TrimSpace returns a substring of s with leading and trailing ASCII spaces removed.
func TrimSpace(s string) string {
	start := 0
	for start < len(s) {
		c := s[start]
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			break
		}
		start++
	}
	end := len(s)
	for end > start {
		c := s[end-1]
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			break
		}
		end--
	}
	return s[start:end]
}
