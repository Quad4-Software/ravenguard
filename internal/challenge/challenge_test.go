// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package challenge_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/challenge"
)

func TestPoWRoundTrip(t *testing.T) {
	m := &challenge.Manager{
		Secret:     []byte("test-secret-16chars"),
		Difficulty: 8,
		CookieName: "rg_clear",
		CookieTTL:  0,
	}
	tok, payload, err := m.Issue("client-a")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := m.ParseToken(payload, "client-a")
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Nonce != tok.Nonce {
		t.Fatal("nonce mismatch")
	}
	if _, err := m.ParseToken(payload, "client-b"); err == nil {
		t.Fatal("expected bind mismatch")
	}
	sol, err := challenge.SolvePoW(parsed.Nonce, parsed.Difficulty)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.VerifyPoW(parsed, strconv.FormatUint(sol, 10)); err != nil {
		t.Fatal(err)
	}
	if err := m.ConsumeNonce(parsed); err != nil {
		t.Fatal(err)
	}
	if err := m.ConsumeNonce(parsed); !errors.Is(err, challenge.ErrReplay) {
		t.Fatalf("expected replay got %v", err)
	}
}

func TestClearanceCookie(t *testing.T) {
	m := &challenge.Manager{
		Secret:     []byte("cookie-secret-16ch"),
		Difficulty: 4,
		CookieName: "rg_clear",
		CookieTTL:  time.Hour,
	}
	c := m.ClearanceCookie("203.0.113.1", "ray123", true)
	if !c.Secure {
		t.Fatal("expected secure cookie")
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(c)
	if !m.HasClearance(r, "203.0.113.1") {
		t.Fatal("expected clearance")
	}
	if m.HasClearance(r, "203.0.113.2") {
		t.Fatal("ip mismatch should fail")
	}
}

func TestTamperedToken(t *testing.T) {
	m := &challenge.Manager{Secret: []byte("test-secret-16chars"), Difficulty: 4}
	_, payload, err := m.Issue("c1")
	if err != nil {
		t.Fatal(err)
	}
	bad := payload + "x"
	if _, err := m.ParseToken(bad, "c1"); err == nil {
		t.Fatal("expected invalid token")
	}
}

func FuzzVerifyPoW(f *testing.F) {
	m := &challenge.Manager{Secret: []byte("fuzz-secret-16char"), Difficulty: 4}
	_, payload, _ := m.Issue("fuzz-client")
	f.Add(payload, "0")
	f.Add("bad", "1")
	f.Fuzz(func(t *testing.T, token, sol string) {
		tok, err := m.ParseToken(token, "fuzz-client")
		if err != nil {
			return
		}
		_ = m.VerifyPoW(tok, sol)
	})
}
