// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
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

func TestForgePathClassCgitAuto(t *testing.T) {
	cases := []struct {
		path string
		want detect.ForgeClass
	}{
		{"/repo/snapshot/repo-main.tar.gz", detect.ForgeHot},
		{"/repo.git/diff/", detect.ForgeHot},
		{"/repo/patch", detect.ForgeHot},
		{"/repo/blame/README", detect.ForgeHot},
		{"/group/repo/snapshot/x.tar.zst", detect.ForgeHot},
		{"/repo/tree/src/main.c", detect.ForgeBrowse},
		{"/repo.git/plain/README.md", detect.ForgeBrowse},
		{"/repo/commit", detect.ForgeBrowse},
		{"/repo/log/qt/grep", detect.ForgeBrowse},
		{"/repo/refs", detect.ForgeBrowse},
		{"/REPO/TAG/v1", detect.ForgeBrowse},
		{"/repo", detect.ForgeNone},
		{"/repo/", detect.ForgeNone},
		{"/about", detect.ForgeNone},
		{"/repo.git/info/refs", detect.ForgeNone},
		{"/repo.git/git-upload-pack", detect.ForgeNone},
		// Deep nesting needs forge_flavor=cgit; auto only checks two depths.
		{"/pub/scm/linux/kernel/git/torvalds/linux.git/commit", detect.ForgeNone},
	}
	for _, tc := range cases {
		got := detect.ForgePathClass(tc.path)
		if got != tc.want {
			t.Fatalf("auto path=%q got=%v want=%v", tc.path, got, tc.want)
		}
	}
}

func TestForgePathClassFlavors(t *testing.T) {
	gitea := detect.ForgeGitea
	cgit := detect.ForgeCgit
	cases := []struct {
		flavor detect.ForgeFlavor
		path   string
		want   detect.ForgeClass
	}{
		{gitea, "/o/r/compare/a...b", detect.ForgeHot},
		{gitea, "/repo/tree", detect.ForgeNone},
		{gitea, "/repo/snapshot/x.tar.gz", detect.ForgeNone},
		{cgit, "/repo/tree/src", detect.ForgeBrowse},
		{cgit, "/repo/snapshot/x.tar.gz", detect.ForgeHot},
		{cgit, "/pub/scm/linux/kernel/git/torvalds/linux.git/commit", detect.ForgeBrowse},
		{cgit, "/pub/scm/linux/kernel/git/torvalds/linux.git/snapshot/linux-6.9.tar.gz", detect.ForgeHot},
		{cgit, "/pub/scm/linux/kernel/git/torvalds/linux.git/plain/Makefile", detect.ForgeBrowse},
		{cgit, "/repo.git/info/refs", detect.ForgeNone},
		{cgit, "/repo.git/git-upload-pack", detect.ForgeNone},
		{cgit, "/", detect.ForgeNone},
		{cgit, "", detect.ForgeNone},
	}
	for _, tc := range cases {
		got := tc.flavor.Classify(tc.path)
		if got != tc.want {
			t.Fatalf("flavor=%v path=%q got=%v want=%v", tc.flavor, tc.path, got, tc.want)
		}
	}
	if detect.ParseForgeFlavor("forgejo") != gitea {
		t.Fatal("forgejo should parse to gitea")
	}
	if detect.ParseForgeFlavor("CGIT") != cgit {
		t.Fatal("CGIT should parse to cgit")
	}
	if detect.ParseForgeFlavor("") != detect.ForgeAuto || detect.ParseForgeFlavor("bogus") != detect.ForgeAuto {
		t.Fatal("unknown flavors should parse to auto")
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
