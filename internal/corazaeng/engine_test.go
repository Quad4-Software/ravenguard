// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package corazaeng

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Quad4-Software/ravenguard/internal/config"
)

func TestEngineInlineRuleBlocks(t *testing.T) {
	eng, err := New(config.CorazaConfig{
		Enabled:        true,
		Mode:           "block",
		CRS:            false,
		MaxBodyInspect: 1 << 20,
		Directives:     `SecRule ARGS:id "@eq 0" "id:1001,phase:1,deny,status:403,msg:'bad id'"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "http://example.com/?id=0", nil)
	res := eng.Evaluate(r)
	if !res.Matched || !res.ShouldBlock {
		t.Fatalf("expected block got %+v", res)
	}
	if res.RuleID != 1001 {
		t.Fatalf("rule id %d", res.RuleID)
	}
}

// Phase-2 rules inspect ARGS, which includes query arguments. Regression:
// requests without a body used to return before ProcessRequestBody, so GET
// attacks in query strings were never evaluated.
func TestEnginePhase2RunsForGetWithoutBody(t *testing.T) {
	eng, err := New(config.CorazaConfig{
		Enabled:        true,
		Mode:           "block",
		CRS:            false,
		MaxBodyInspect: 1 << 20,
		Directives:     `SecRule ARGS:q "@contains attack" "id:1005,phase:2,deny,status:403"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "http://example.com/?q=attack", nil)
	res := eng.Evaluate(r)
	if !res.Matched || !res.ShouldBlock {
		t.Fatalf("phase-2 GET arg attack must block, got %+v", res)
	}
	if res.RuleID != 1005 {
		t.Fatalf("rule id %d", res.RuleID)
	}
}

func TestEnginePhase2RunsForEmptyBodyPost(t *testing.T) {
	eng, err := New(config.CorazaConfig{
		Enabled:        true,
		Mode:           "block",
		CRS:            false,
		MaxBodyInspect: 1 << 20,
		Directives:     `SecRule ARGS:x "@eq 9" "id:1006,phase:2,deny,status:403"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "http://example.com/?x=9", nil)
	res := eng.Evaluate(r)
	if !res.Matched || !res.ShouldBlock {
		t.Fatalf("phase-2 must run for bodyless POST, got %+v", res)
	}
}

func newCRSEngine(t *testing.T, mode string) *Engine {
	t.Helper()
	eng, err := New(config.CorazaConfig{
		Enabled:        true,
		Mode:           mode,
		CRS:            true,
		Paranoia:       1,
		MaxBodyInspect: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func TestEngineCRSBlocksQueryAttacks(t *testing.T) {
	eng := newCRSEngine(t, "block")
	cases := map[string]string{
		"sqli":      "http://example.com/?id=1%27%20OR%20%271%27=%271",
		"xss":       "http://example.com/?q=%3Cscript%3Ealert(1)%3C/script%3E",
		"traversal": "http://example.com/?p=../../../../etc/passwd",
		"rce":       "http://example.com/?cmd=;cat%20/etc/passwd",
	}
	for name, u := range cases {
		r := httptest.NewRequest(http.MethodGet, u, nil)
		res := eng.Evaluate(r)
		if !res.Matched || !res.ShouldBlock {
			t.Errorf("%s: GET query attack must block, got %+v", name, res)
		}
	}
}

func TestEngineCRSCleanGetPasses(t *testing.T) {
	eng := newCRSEngine(t, "block")
	r := httptest.NewRequest(http.MethodGet, "http://example.com/search?q=hello+world&page=2", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0")
	res := eng.Evaluate(r)
	if res.Matched {
		t.Fatalf("clean GET must pass, got %+v", res)
	}
}

func TestEngineCRSDetectModeDoesNotBlock(t *testing.T) {
	eng := newCRSEngine(t, "detect")
	r := httptest.NewRequest(http.MethodGet, "http://example.com/?id=1%27%20OR%20%271%27=%271", nil)
	res := eng.Evaluate(r)
	if !res.Matched {
		t.Fatal("detect mode must still match")
	}
	if res.ShouldBlock {
		t.Fatal("detect mode must not block")
	}
}

func TestEngineSkipPrefixBypasses(t *testing.T) {
	eng, err := New(config.CorazaConfig{
		Enabled:          true,
		Mode:             "block",
		CRS:              false,
		MaxBodyInspect:   1 << 20,
		SkipPathPrefixes: []string{"/_rg"},
		Directives:       `SecRule ARGS:q "@contains attack" "id:1007,phase:2,deny,status:403"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "http://example.com/_rg/challenge?q=attack", nil)
	res := eng.Evaluate(r)
	if res.Matched {
		t.Fatalf("skip prefix must bypass evaluation, got %+v", res)
	}
}

// After inspection the upstream must still receive the complete body,
// including bytes beyond the inspection cap.
func TestEngineBodyPreservedForUpstream(t *testing.T) {
	eng := newCRSEngine(t, "block")
	body := strings.Repeat("a", 4096)
	r := httptest.NewRequest(http.MethodPost, "http://example.com/submit", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res := eng.Evaluate(r)
	if res.Matched {
		t.Fatalf("clean POST must pass, got %+v", res)
	}
	got, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Fatalf("body truncated: got %d bytes want %d", len(got), len(body))
	}
}

func TestEngineOversizedBodyStillFullyPreserved(t *testing.T) {
	eng, err := New(config.CorazaConfig{
		Enabled:        true,
		Mode:           "block",
		CRS:            false,
		MaxBodyInspect: 64,
		Directives:     `SecRule REQUEST_BODY "@contains never" "id:1008,phase:2,deny,status:403"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("b", 2048)
	r := httptest.NewRequest(http.MethodPost, "http://example.com/submit", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = eng.Evaluate(r)
	got, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Fatalf("upstream body truncated: got %d bytes want %d", len(got), len(body))
	}
}

func TestEngineDetectMode(t *testing.T) {
	eng, err := New(config.CorazaConfig{
		Enabled:        true,
		Mode:           "detect",
		CRS:            false,
		MaxBodyInspect: 1 << 20,
		Directives:     `SecRule ARGS:id "@eq 0" "id:1002,phase:1,deny,status:403"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "http://example.com/?id=0", nil)
	res := eng.Evaluate(r)
	if !res.Matched || res.ShouldBlock {
		t.Fatalf("detect should match without block %+v", res)
	}
}

func TestEngineDisabled(t *testing.T) {
	eng, err := New(config.CorazaConfig{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	if eng.Enabled() {
		t.Fatal("expected disabled")
	}
}

func TestUpdateLiveWithoutRules(t *testing.T) {
	eng, err := New(config.CorazaConfig{Enabled: false})
	if err != nil {
		t.Fatal(err)
	}
	eng.UpdateLive(true, "block")
	if eng.Enabled() || eng.Loaded() {
		t.Fatal("live enable without loaded rules must stay off")
	}
}

func TestPathSkipped(t *testing.T) {
	if !pathSkipped("/_rg", "/_rg") {
		t.Fatal("exact prefix")
	}
	if !pathSkipped("/_rg/challenge", "/_rg") {
		t.Fatal("child of prefix")
	}
	if pathSkipped("/_rgx", "/_rg") {
		t.Fatal("must not match sibling prefix")
	}
	if !pathSkipped("/_rg/x", "/_rg/") {
		t.Fatal("trailing slash prefix")
	}
	if pathSkipped("/_rg", "/_rg/") {
		t.Fatal("exact /_rg should not match /_rg/ prefix")
	}
}

func TestSanitizeRulesPath(t *testing.T) {
	if _, err := sanitizeRulesPath("../etc", true); err == nil {
		t.Fatal("expected escape reject")
	}
	if _, err := sanitizeRulesPath("rules\nInclude /etc", false); err == nil {
		t.Fatal("expected newline reject")
	}
	got, err := sanitizeRulesPath("./rules", true)
	if err != nil || got != "rules" {
		t.Fatalf("got %q err %v", got, err)
	}
}

// slashFS must normalize backslash-separated names, which is what Coraza's
// filepath.Join produces for include paths on Windows.
func TestSlashFSNormalizesSeparators(t *testing.T) {
	inner := fstest.MapFS{
		"a/b/c.conf": &fstest.MapFile{Data: []byte("x")},
	}
	s := slashFS{inner}
	for _, name := range []string{`a\b\c.conf`, `./a\b\c.conf`, "a/b/c.conf"} {
		data, err := s.ReadFile(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(data) != "x" {
			t.Fatalf("%s: %q", name, data)
		}
		if _, err := s.Stat(name); err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
	}
	if _, err := s.ReadDir(`a\b`); err != nil {
		t.Fatalf("readdir: %v", err)
	}
}
