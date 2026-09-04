// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package corazaeng

import (
	"net/http"
	"net/http/httptest"
	"testing"

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
