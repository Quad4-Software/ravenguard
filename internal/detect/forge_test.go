// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package detect_test

import (
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/detect"
)

func TestForgePathClass(t *testing.T) {
	cases := []struct {
		path string
		want detect.ForgeClass
	}{
		{"/o/r/compare/a...b", detect.ForgeHot},
		{"/o/r/compare/a...b.diff", detect.ForgeHot},
		{"/o/r/blame/branch/f.go", detect.ForgeHot},
		{"/o/r/archive/main.zip", detect.ForgeHot},
		{"/o/r/archive/main.tar.gz", detect.ForgeHot},
		{"/o/r/archive/main.bundle", detect.ForgeHot},
		{"/api/v1/repos/o/r/compare/a...b", detect.ForgeHot},
		{"/api/v1/repos/o/r/archive/main.zip", detect.ForgeHot},
		{"/api/v1/repos/o/r/git/trees/abc", detect.ForgeHot},
		{"/api/v1/repos/o/r/git/blobs/abc", detect.ForgeHot},
		{"/O/R/COMPARE/a...b", detect.ForgeHot},

		{"/o/r/src/branch/main", detect.ForgeBrowse},
		{"/o/r/raw/branch/main/f", detect.ForgeBrowse},
		{"/o/r/media/branch/main/f", detect.ForgeBrowse},
		{"/o/r/commit/abc", detect.ForgeBrowse},
		{"/o/r/commits/branch/main", detect.ForgeBrowse},
		{"/api/v1/repos/o/r/raw/main/f", detect.ForgeBrowse},

		{"/o/r", detect.ForgeNone},
		{"/o/r/", detect.ForgeNone},
		{"/o/r/issues", detect.ForgeNone},
		{"/o/r/pulls/1", detect.ForgeNone},
		{"/o/r/settings", detect.ForgeNone},
		{"/explore/repos", detect.ForgeNone},
		{"/user/login", detect.ForgeNone},
		{"/_rg/challenge", detect.ForgeNone},
		{"/products/shoes", detect.ForgeNone},
		{"/o/r.git/info/refs", detect.ForgeNone},
		{"/o/r.git/git-upload-pack", detect.ForgeNone},
		{"/o/r.git/git-receive-pack", detect.ForgeNone},
		{"/info/refs", detect.ForgeNone},
		{"", detect.ForgeNone},
		{"/", detect.ForgeNone},
	}
	for _, tc := range cases {
		got := detect.ForgePathClass(tc.path)
		if got != tc.want {
			t.Fatalf("path=%q got=%v want=%v", tc.path, got, tc.want)
		}
	}
}

func TestForgePathClassAllocs(t *testing.T) {
	paths := []string{
		"/owner/repo/compare/a...b",
		"/owner/repo/src/branch/main",
		"/owner/repo",
		"/owner/repo.git/info/refs",
		"/api/v1/repos/o/r/git/trees/abc",
		"/products/shoes",
	}
	for _, p := range paths {
		n := testing.AllocsPerRun(1000, func() {
			_ = detect.ForgePathClass(p)
		})
		if n != 0 {
			t.Fatalf("path=%q allocs=%v want 0", p, n)
		}
	}
}
