// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package router

import (
	"strings"
	"testing"
)

func FuzzPrefixMatch(f *testing.F) {
	// Property: matchPrefix(path, prefix) true implies path equals prefix,
	// or path starts with prefix plus an additional path segment.
	seeds := [][2]string{
		{"/", "/"},
		{"/api", "/api"},
		{"/api/v1", "/api"},
		{"/api", "/api/v1"},
		{"/api/v1/users", "/api"},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, path, prefix string) {
		// Normalize: the implementation treats empty or bare prefix as root.
		got := matchPrefix(path, prefix)
		if !got {
			return
		}
		p := prefix
		if p == "" || p == "/" {
			return // root matches everything
		}
		if path == p {
			return
		}
		trimmed := strings.TrimSuffix(p, "/")
		// Metamorphic / differential oracle: a matching path is either the
		// trimmed prefix exactly, or it starts with the trimmed prefix plus '/'.
		if path == trimmed {
			return
		}
		if strings.HasPrefix(path, trimmed+"/") {
			return
		}
		t.Fatalf("matchPrefix(%q, %q) = true but path is not a prefix match", path, prefix)
	})
}
