// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

package pipeline_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/config"
)

const aiUA = "AIWebIndex/1.0"

func TestAIPolicyBlock(t *testing.T) {
	h := forgeTestHandler(t, func(cfg *config.Config) {
		cfg.Detect.AICrawlerPolicy = "block"
	})
	req := httptest.NewRequest(http.MethodGet, "/products/x", nil)
	req.Header.Set("User-Agent", aiUA)
	req.RemoteAddr = "192.0.2.140:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("ai block policy: got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Access denied") {
		t.Fatal("ai block policy should render the block page")
	}
}

func TestAIPolicyAllow(t *testing.T) {
	h := forgeTestHandler(t, func(cfg *config.Config) {
		cfg.Detect.AICrawlerPolicy = "allow"
	})
	req := httptest.NewRequest(http.MethodGet, "/products/x", nil)
	req.Header.Set("User-Agent", aiUA)
	req.RemoteAddr = "192.0.2.141:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("ai allow policy: got %d", rr.Code)
	}
}

func TestAIPolicyPay(t *testing.T) {
	h := forgeTestHandler(t, func(cfg *config.Config) {
		cfg.Detect.AICrawlerPolicy = "pay"
		cfg.Detect.AIPay.PayTo = "0xTestRecipient"
		cfg.Detect.AIPay.Amount = "10000"
		cfg.Detect.AIPay.Network = "base"
		cfg.Detect.AIPay.Asset = "0xUSDC"
	})
	req := httptest.NewRequest(http.MethodGet, "/products/x", nil)
	req.Header.Set("User-Agent", aiUA)
	req.RemoteAddr = "192.0.2.142:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusPaymentRequired {
		t.Fatalf("ai pay policy: got %d body=%s", rr.Code, rr.Body.String()[:min(200, len(rr.Body.String()))])
	}
	var doc struct {
		X402Version int `json:"x402Version"`
		Accepts     []struct {
			PayTo             string `json:"payTo"`
			MaxAmountRequired string `json:"maxAmountRequired"`
			Network           string `json:"network"`
		} `json:"accepts"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
		t.Fatalf("402 body not an x402 doc: %v", err)
	}
	if len(doc.Accepts) == 0 || doc.Accepts[0].PayTo != "0xTestRecipient" {
		t.Fatalf("missing accept entry: %+v", doc)
	}
}

func TestRobotsSignals(t *testing.T) {
	h := forgeTestHandler(t, func(cfg *config.Config) {
		cfg.Site.Robots = "index, follow"
		cfg.Site.RobotsAI = "disallow"
		cfg.Site.PublicURL = "https://example.com"
	})
	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	req.RemoteAddr = "192.0.2.143:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	body := rr.Body.String()
	for _, want := range []string{
		"Content-Signal: search=yes, ai-input=yes, ai-train=no",
		"User-agent: GPTBot",
		"User-agent: CCBot",
		"User-agent: AIWebIndex",
		"Sitemap: https://example.com/sitemap.xml",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("robots.txt missing %q:\n%s", want, body)
		}
	}
}

func TestRobotsSignalsOff(t *testing.T) {
	h := forgeTestHandler(t, func(cfg *config.Config) {
		cfg.Site.RobotsAI = "off"
	})
	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	req.RemoteAddr = "192.0.2.144:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if strings.Contains(rr.Body.String(), "Content-Signal") || strings.Contains(rr.Body.String(), "GPTBot") {
		t.Fatal("robots_ai=off still emitted AI declarations")
	}
}
