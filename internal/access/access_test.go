// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package access

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestIPAllowlist(t *testing.T) {
	m := NewManager([]byte("test-secret-key-32bytes-long!!!!"))
	m.Replace([]Policy{{
		ID:   "p1",
		Name: "office",
		Mode: ModeAll,
		Rules: []Rule{{
			Type:  RuleIPAllowlist,
			CIDRs: []string{"198.51.100.0/24"},
		}},
		CookieTTL: time.Hour,
	}})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	ok := m.Check(r, "p1", "bind-a", net.ParseIP("198.51.100.10"))
	if !ok.OK {
		t.Fatalf("expected allow got %+v", ok)
	}
	denyRes := m.Check(r, "p1", "bind-a", net.ParseIP("203.0.113.5"))
	if denyRes.OK || denyRes.NeedForm || denyRes.Status != http.StatusForbidden {
		t.Fatalf("expected deny got %+v", denyRes)
	}
}

func TestHeaderRule(t *testing.T) {
	m := NewManager([]byte("test-secret-key-32bytes-long!!!!"))
	m.Replace([]Policy{{
		ID: "hdr",
		Rules: []Rule{{
			Type:        RuleHeader,
			HeaderName:  "X-Site-Key",
			HeaderValue: "alpha",
		}},
	}})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Site-Key", "alpha")
	res := m.Check(r, "hdr", "b1", nil)
	if !res.OK {
		t.Fatalf("expected allow got %+v", res)
	}

	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set("X-Site-Key", "beta")
	res2 := m.Check(r2, "hdr", "b1", nil)
	if res2.OK || res2.Status != http.StatusForbidden {
		t.Fatalf("expected deny got %+v", res2)
	}
}

func TestCookieRoundtrip(t *testing.T) {
	m := NewManager([]byte("test-secret-key-32bytes-long!!!!"))
	m.Replace([]Policy{{
		ID:        "auth",
		CookieTTL: time.Hour,
		Rules: []Rule{{
			Type:   RulePassword,
			Secret: "hunter22",
		}},
	}})

	r0 := httptest.NewRequest(http.MethodGet, "/", nil)
	before := m.Check(r0, "auth", "client-1", nil)
	if !before.NeedForm {
		t.Fatalf("expected need form got %+v", before)
	}

	rr := httptest.NewRecorder()
	m.IssueCookie(rr, "auth", "client-1", false)
	res := rr.Result()
	defer res.Body.Close()
	var cookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == CookieName {
			cookie = c
			break
		}
	}
	if cookie == nil {
		t.Fatal("missing rg_access cookie")
	}
	parts := strings.Split(cookie.Value, "|")
	if len(parts) != 4 {
		t.Fatalf("cookie format want 4 fields got %d: %q", len(parts), cookie.Value)
	}

	r1 := httptest.NewRequest(http.MethodGet, "/", nil)
	r1.AddCookie(cookie)
	after := m.Check(r1, "auth", "client-1", nil)
	if !after.OK {
		t.Fatalf("expected allow with cookie got %+v", after)
	}

	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.AddCookie(cookie)
	wrongBind := m.Check(r2, "auth", "other-client", nil)
	if wrongBind.OK {
		t.Fatal("cookie must not validate for different bind id")
	}
}

func TestHashSecretPINAndPassword(t *testing.T) {
	pinHash, err := HashSecret("1234", MinPINLen)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySecret(pinHash, "1234"); err != nil {
		t.Fatal(err)
	}
	if _, err := HashSecret("123", MinPINLen); err == nil {
		t.Fatal("expected short pin error")
	}
	passHash, err := HashSecret("password1", MinPasswordLen)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySecret(passHash, "password1"); err != nil {
		t.Fatal(err)
	}
	if _, err := HashSecret("short", MinPasswordLen); err == nil {
		t.Fatal("expected short password error")
	}
}

func TestVerifyForm(t *testing.T) {
	m := NewManager([]byte("test-secret-key-32bytes-long!!!!"))
	m.Replace([]Policy{{
		ID: "gate",
		Rules: []Rule{{
			Type:   RulePIN,
			Secret: "4242",
		}},
	}})
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	if !m.VerifyForm(r, "gate", "b", "4242") {
		t.Fatal("expected pin match")
	}
	if m.VerifyForm(r, "gate", "b", "9999") {
		t.Fatal("expected pin mismatch")
	}
}
