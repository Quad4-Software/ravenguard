// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package pipeline_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/blocklist"
	"github.com/Quad4-Software/ravenguard/internal/challenge"
	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/pipeline"
	"github.com/Quad4-Software/ravenguard/internal/ui"
)

func TestAttackModeColdGETForcesInteractive(t *testing.T) {
	cfg := config.Default()
	cfg.Challenge.Secret = testSecret
	cfg.Challenge.Difficulty = 8
	cfg.Challenge.Mode = "attack"
	cfg.Challenge.EnvProbe = "off"
	cfg.Challenge.Captcha.Enabled = true
	cfg.Challenge.Captcha.Provider = "stub"
	cfg.Challenge.Captcha.Token = "ok"
	cfg.Detect.Enabled = false
	cfg.RateLimit.Enabled = false
	cfg.Trust.Mode = "edge"
	cfg.Privacy.HashClientIP = false
	pages, err := ui.New(ui.SiteFromConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	chal := &challenge.Manager{
		Secret:     []byte(cfg.Challenge.Secret),
		Difficulty: 8,
		Algorithm:  "sha256",
		CookieName: "rg_clear",
		CookieTTL:  time.Hour,
		Captcha:    challenge.StubCaptcha{Token: "ok"},
	}
	h := pipeline.New(cfg, blocklist.New(), nil, nil, chal, pages,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }),
		nil, nil, nil, testPriv(cfg), nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/_rg/v1/challenge", nil)
	req.RemoteAddr = "198.51.100.9:1"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("issue status=%d body=%s", rr.Code, rr.Body.String())
	}
	var ch challenge.Challenge
	if err := json.Unmarshal(rr.Body.Bytes(), &ch); err != nil {
		t.Fatal(err)
	}
	if ch.Gate != challenge.GateInteractive {
		t.Fatalf("attack cold GET gate=%q want interactive", ch.Gate)
	}

	sol, err := challenge.SolveChallenge(ch)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := challenge.EncodePayload(challenge.Payload{
		V: ch.V, Algorithm: ch.Algorithm, Challenge: ch.Challenge, Salt: ch.Salt,
		Difficulty: ch.Difficulty, MaxNumber: ch.MaxNumber, Expires: ch.Expires,
		Bind: ch.Bind, Gate: ch.Gate, Params: ch.Params, Signature: ch.Signature,
		Solution: strconv.FormatUint(sol, 10),
		Env:      challenge.EnvAttestation{Interacted: true, SolveMs: 200},
	})
	if err != nil {
		t.Fatal(err)
	}
	noCaptcha, _ := json.Marshal(map[string]any{"payload": raw})
	preq := httptest.NewRequest(http.MethodPost, "/_rg/challenge", bytes.NewReader(noCaptcha))
	preq.Header.Set("Content-Type", "application/json")
	preq.RemoteAddr = "198.51.100.9:1"
	prr := httptest.NewRecorder()
	h.ServeHTTP(prr, preq)
	if prr.Code == http.StatusOK {
		t.Fatal("expected captcha required on attack clearance")
	}

	req2 := httptest.NewRequest(http.MethodGet, "/_rg/v1/challenge", nil)
	req2.RemoteAddr = "198.51.100.9:1"
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	var ch2 challenge.Challenge
	if err := json.Unmarshal(rr2.Body.Bytes(), &ch2); err != nil {
		t.Fatal(err)
	}
	sol2, err := challenge.SolveChallenge(ch2)
	if err != nil {
		t.Fatal(err)
	}
	raw2, err := challenge.EncodePayload(challenge.Payload{
		V: ch2.V, Algorithm: ch2.Algorithm, Challenge: ch2.Challenge, Salt: ch2.Salt,
		Difficulty: ch2.Difficulty, MaxNumber: ch2.MaxNumber, Expires: ch2.Expires,
		Bind: ch2.Bind, Gate: ch2.Gate, Params: ch2.Params, Signature: ch2.Signature,
		Solution: strconv.FormatUint(sol2, 10),
		Env:      challenge.EnvAttestation{Interacted: true, SolveMs: 200},
	})
	if err != nil {
		t.Fatal(err)
	}
	withCaptcha, _ := json.Marshal(map[string]any{"payload": raw2, "captcha": "ok"})
	preq2 := httptest.NewRequest(http.MethodPost, "/_rg/challenge", bytes.NewReader(withCaptcha))
	preq2.Header.Set("Content-Type", "application/json")
	preq2.RemoteAddr = "198.51.100.9:1"
	prr2 := httptest.NewRecorder()
	h.ServeHTTP(prr2, preq2)
	if prr2.Code != http.StatusOK {
		t.Fatalf("captcha ok should clear post=%d %s", prr2.Code, prr2.Body.String())
	}
}

func TestCaptchaEnabledForcesInteractiveIssue(t *testing.T) {
	cfg := config.Default()
	cfg.Challenge.Secret = testSecret
	cfg.Challenge.Difficulty = 8
	cfg.Challenge.Mode = "always"
	cfg.Challenge.EnvProbe = "off"
	cfg.Challenge.Captcha.Enabled = true
	cfg.Challenge.Captcha.Provider = "stub"
	cfg.Challenge.Captcha.Token = "ok"
	cfg.Detect.Enabled = false
	cfg.RateLimit.Enabled = false
	cfg.Trust.Mode = "edge"
	cfg.Privacy.HashClientIP = false
	pages, err := ui.New(ui.SiteFromConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	chal := &challenge.Manager{
		Secret: []byte(cfg.Challenge.Secret), Difficulty: 8, Algorithm: "sha256",
		CookieName: "rg_clear", CookieTTL: time.Hour, Captcha: challenge.StubCaptcha{Token: "ok"},
	}
	h := pipeline.New(cfg, blocklist.New(), nil, nil, chal, pages,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }),
		nil, nil, nil, testPriv(cfg), nil, nil)

	irr := httptest.NewRecorder()
	ireq := httptest.NewRequest(http.MethodGet, "/_rg/v1/challenge", nil)
	ireq.RemoteAddr = "198.51.100.11:1"
	h.ServeHTTP(irr, ireq)
	var ch challenge.Challenge
	if err := json.Unmarshal(irr.Body.Bytes(), &ch); err != nil {
		t.Fatal(err)
	}
	if ch.Gate != challenge.GateInteractive {
		t.Fatalf("captcha enabled cold GET gate=%q want interactive", ch.Gate)
	}
}
