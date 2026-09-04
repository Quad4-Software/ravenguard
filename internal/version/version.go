// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

// Package version reports build identity for hub and proxy binaries.
package version

import (
	"runtime/debug"
	"strings"
)

// Commit may be set at link time with
// -X github.com/Quad4-Software/ravenguard/internal/version.Commit=<sha>.
var Commit = ""

// Version may be set at link time with
// -X github.com/Quad4-Software/ravenguard/internal/version.Version=<tag>.
var Version = ""

// Short returns a short commit id for display and agent reporting.
func Short() string {
	if c := shortSHA(Commit); c != "" {
		return c
	}
	if info, ok := debug.ReadBuildInfo(); ok && info != nil {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				if c := shortSHA(s.Value); c != "" {
					return c
				}
			}
		}
	}
	return "unknown"
}

// Release returns the stamped release tag or "dev".
func Release() string {
	if v := strings.TrimSpace(Version); v != "" {
		return v
	}
	if info, ok := debug.ReadBuildInfo(); ok && info != nil {
		v := strings.TrimSpace(info.Main.Version)
		if v != "" && v != "(devel)" {
			return v
		}
	}
	return "dev"
}

// Label is release plus short commit for compact UI display.
func Label() string {
	rel := Release()
	sha := Short()
	if rel == "dev" {
		return sha
	}
	if sha == "unknown" {
		return rel
	}
	return rel + " " + sha
}

func shortSHA(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) > 7 {
		return s[:7]
	}
	return s
}
