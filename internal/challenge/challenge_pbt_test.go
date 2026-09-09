// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package challenge_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/challenge"
)

// pbt runs a seeded property-based test loop with count iterations.
func pbt(t *testing.T, name string, seed int64, count int, f func(r *rand.Rand) (bool, string)) {
	t.Helper()
	r := rand.New(rand.NewSource(seed))
	for i := range count {
		ok, msg := f(r)
		if !ok {
			t.Fatalf("%s failed at iteration %d: %s", name, i, msg)
		}
	}
}

func randomString(r *rand.Rand, minLen, maxLen int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if maxLen < minLen {
		maxLen = minLen
	}
	n := minLen
	if maxLen > minLen {
		n += r.Intn(maxLen - minLen + 1)
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[r.Intn(len(letters))]
	}
	return string(b)
}

func randomSolutionString(r *rand.Rand) string {
	if r.Intn(2) == 0 {
		return randomString(r, 0, 20)
	}
	const digits = "0123456789"
	n := r.Intn(21)
	b := make([]byte, n)
	for i := range b {
		b[i] = digits[r.Intn(len(digits))]
	}
	return string(b)
}

func randomAlgorithm(r *rand.Rand) string {
	choices := []string{
		"", "sha256", "sha-256", "SHA-256", "  sha-256  ",
		"pbkdf2", "pbkdf2-sha256", "PBKDF2-SHA256",
		"argon2id", "adaptive", "scrypt", "whirlpool", "md5",
	}
	return choices[r.Intn(len(choices))]
}

func randomRisk(r *rand.Rand) challenge.RiskLevel {
	return challenge.RiskLevel(r.Intn(3))
}

func randomGate(r *rand.Rand) string {
	choices := []string{"", "invisible", "interactive", "attack", "  interactive  "}
	return choices[r.Intn(len(choices))]
}

func randomDifficulty(r *rand.Rand) int {
	// Covers negative, normal, and large-but-safe positive values.
	return r.Intn(2000) - 100
}

// refTokenSignature is an independent re-implementation of Manager.sign.
func refTokenSignature(secret []byte, nonce string, issued int64, diff int, clientID string) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(nonce))
	h.Write([]byte("."))
	h.Write(strconv.AppendInt(nil, issued, 10))
	h.Write([]byte("."))
	h.Write(strconv.AppendInt(nil, int64(diff), 10))
	h.Write([]byte("."))
	h.Write([]byte(clientID))
	return hex.EncodeToString(h.Sum(nil))
}

// refCheckPoW is an independent re-implementation of the SHA-256 PoW check.
func refCheckPoW(nonce string, solution uint64, difficulty int) bool {
	if difficulty < 0 {
		return false
	}
	h := sha256.New()
	h.Write([]byte(nonce))
	h.Write([]byte(":"))
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], solution)
	h.Write(b[:])
	return challenge.LeadingZeroBits(h.Sum(nil)) >= difficulty
}

// refVerifyPoW compares a solution string against the reference PoW check.
func refVerifyPoW(tok challenge.Token, sol string) error {
	n, err := strconv.ParseUint(sol, 10, 64)
	if err != nil {
		return challenge.ErrBadSolution
	}
	if refCheckPoW(tok.Nonce, n, tok.Difficulty) {
		return nil
	}
	return challenge.ErrBadSolution
}

// refCookieMAC is an independent re-implementation of Manager.mac.
func refCookieMAC(secret []byte, payload string) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

func TestPBTGeneratedTokenVerifies(t *testing.T) {
	pbt(t, "PBTGeneratedTokenVerifies", 1, 30, func(r *rand.Rand) (bool, string) {
		diff := 1 + r.Intn(8)
		clientID := randomString(r, 1, 24)
		m := &challenge.Manager{Secret: []byte("pbt-secret-16bytes"), Difficulty: diff, CookieName: "pbt", CookieTTL: time.Hour}

		tok, payload, err := m.Issue(clientID)
		if err != nil {
			return false, fmt.Sprintf("issue: %v", err)
		}
		parsed, err := m.ParseToken(payload, clientID)
		if err != nil {
			return false, fmt.Sprintf("parse: %v", err)
		}
		if parsed.Nonce != tok.Nonce || parsed.IssuedAt != tok.IssuedAt || parsed.Difficulty != tok.Difficulty {
			return false, "parsed token does not match issued token"
		}

		sol, err := challenge.SolvePoW(parsed.Nonce, parsed.Difficulty)
		if err != nil {
			return false, fmt.Sprintf("solve: %v", err)
		}
		solStr := strconv.FormatUint(sol, 10)
		if err := m.VerifyPoW(parsed, solStr); err != nil {
			return false, fmt.Sprintf("verify: %v", err)
		}
		if !refCheckPoW(parsed.Nonce, sol, parsed.Difficulty) {
			return false, "reference oracle rejected a valid solution"
		}

		// Independent oracle: the token signature must match a simple HMAC reimplementation.
		parts := strings.Split(payload, ".")
		if len(parts) != 4 {
			return false, "token payload does not have four parts"
		}
		wantSig := refTokenSignature(m.Secret, parts[0], parsed.IssuedAt, parsed.Difficulty, clientID)
		if parts[3] != wantSig {
			return false, "token signature does not match independent oracle"
		}

		return true, ""
	})
}

func TestPBTTokenTamperDetection(t *testing.T) {
	pbt(t, "PBTTokenTamperDetection", 2, 20, func(r *rand.Rand) (bool, string) {
		diff := 1 + r.Intn(8)
		clientID := randomString(r, 1, 24)
		m := &challenge.Manager{Secret: []byte("pbt-secret-16bytes"), Difficulty: diff, CookieName: "pbt", CookieTTL: time.Hour}

		_, payload, err := m.Issue(clientID)
		if err != nil {
			return false, fmt.Sprintf("issue: %v", err)
		}
		if _, err := m.ParseToken(payload, clientID); err != nil {
			return false, fmt.Sprintf("valid token did not parse: %v", err)
		}

		// Metamorphic invariant: modifying any single byte invalidates the token.
		b := []byte(payload)
		for i := range b {
			c := b[i]
			b[i] = c ^ 0xff
			if _, err := m.ParseToken(string(b), clientID); err == nil {
				b[i] = c
				return false, fmt.Sprintf("byte flip at position %d did not invalidate token", i)
			}
			b[i] = c
		}
		return true, ""
	})
}

func TestPBTVerifyPoWDifferential(t *testing.T) {
	pbt(t, "PBTVerifyPoWDifferential", 3, 50, func(r *rand.Rand) (bool, string) {
		diff := 1 + r.Intn(8)
		clientID := randomString(r, 1, 24)
		m := &challenge.Manager{Secret: []byte("pbt-secret-16bytes"), Difficulty: diff, CookieName: "pbt", CookieTTL: time.Hour}

		_, payload, err := m.Issue(clientID)
		if err != nil {
			return false, fmt.Sprintf("issue: %v", err)
		}
		parsed, err := m.ParseToken(payload, clientID)
		if err != nil {
			return false, fmt.Sprintf("parse: %v", err)
		}

		sol := randomSolutionString(r)

		// Metamorphic: VerifyPoW must be deterministic for the same inputs.
		got1 := m.VerifyPoW(parsed, sol)
		got2 := m.VerifyPoW(parsed, sol)
		if (got1 == nil) != (got2 == nil) {
			return false, "VerifyPoW is not deterministic"
		}

		// Differential oracle: compare implementation to the independent reference.
		want := refVerifyPoW(parsed, sol)
		if (want == nil) != (got1 == nil) {
			return false, fmt.Sprintf("differential mismatch: ref=%v impl=%v sol=%q", want, got1, sol)
		}
		return true, ""
	})
}

func TestPBTExpiredTokenRejected(t *testing.T) {
	pbt(t, "PBTExpiredTokenRejected", 4, 30, func(r *rand.Rand) (bool, string) {
		clientID := randomString(r, 1, 24)
		m := &challenge.Manager{Secret: []byte("pbt-secret-16bytes"), CookieName: "pbt", CookieTTL: time.Hour}

		nonce := "0123456789abcdef0123456789abcdef"
		issued := int64(1) // far in the past
		diff := 4
		sig := refTokenSignature(m.Secret, nonce, issued, diff, clientID)
		payload := fmt.Sprintf("%s.%d.%d.%s", nonce, issued, diff, sig)

		_, err := m.ParseToken(payload, clientID)
		if !errors.Is(err, challenge.ErrExpired) {
			return false, fmt.Sprintf("expected ErrExpired, got %v", err)
		}
		return true, ""
	})
}

func TestPBTAdaptiveSelection(t *testing.T) {
	pbt(t, "PBTAdaptiveSelection", 5, 50, func(r *rand.Rand) (bool, string) {
		alg := randomAlgorithm(r)
		diff := randomDifficulty(r)
		risk := randomRisk(r)
		gate := randomGate(r)
		m := &challenge.Manager{Secret: []byte("pbt-secret-16bytes"), Difficulty: diff, Algorithm: alg, CookieName: "pbt", CookieTTL: time.Hour}

		const reps = 5
		var first challenge.Challenge
		for i := range reps {
			ch, err := m.IssueChallenge("client", risk, gate)
			if err != nil {
				return false, fmt.Sprintf("issue: %v", err)
			}
			if ch.V != challenge.ProtocolVersion {
				return false, "challenge protocol version mismatch"
			}
			if i == 0 {
				first = ch
			} else if ch.Algorithm != first.Algorithm || ch.Difficulty != first.Difficulty {
				return false, fmt.Sprintf("non-deterministic selection: first %s/%d vs later %s/%d", first.Algorithm, first.Difficulty, ch.Algorithm, ch.Difficulty)
			}
			switch ch.Algorithm {
			case challenge.AlgoSHA256, challenge.AlgoPBKDF2SHA256, challenge.AlgoArgon2id:
			default:
				return false, fmt.Sprintf("selected unknown algorithm %q", ch.Algorithm)
			}
			if ch.Difficulty < 0 {
				return false, fmt.Sprintf("negative difficulty %d", ch.Difficulty)
			}
			upper := diff
			if upper < 0 {
				upper = 28
			}
			if upper < 28 {
				upper = 28
			}
			if ch.Difficulty > upper {
				return false, fmt.Sprintf("difficulty %d exceeds upper bound %d", ch.Difficulty, upper)
			}
			if ch.MaxNumber == 0 || ch.MaxNumber > 1<<32 {
				return false, fmt.Sprintf("maxnumber %d out of bounds", ch.MaxNumber)
			}
		}
		return true, ""
	})
}

func TestAdaptiveAdversarialInputs(t *testing.T) {
	cases := []struct {
		name     string
		alg      string
		diff     int
		risk     challenge.RiskLevel
		wantAlgo string
		wantDiff int
	}{
		{"neg-adaptive-low", "adaptive", -10, challenge.RiskLow, challenge.AlgoSHA256, 16},
		{"neg-adaptive-elev", "adaptive", -10, challenge.RiskElevated, challenge.AlgoPBKDF2SHA256, 16},
		{"neg-adaptive-high", "adaptive", -10, challenge.RiskHigh, challenge.AlgoPBKDF2SHA256, 20},
		{"huge-adaptive-high", "adaptive", 1000, challenge.RiskHigh, challenge.AlgoPBKDF2SHA256, 28},
		{"maxint-adaptive-high", "adaptive", math.MaxInt, challenge.RiskHigh, challenge.AlgoPBKDF2SHA256, 28},
		{"minint-adaptive-low", "adaptive", math.MinInt, challenge.RiskLow, challenge.AlgoSHA256, 16},
		{"huge-sha256", "sha256", 1000, challenge.RiskLow, challenge.AlgoSHA256, 1000},
		{"huge-pbkdf2", "pbkdf2", 1000, challenge.RiskHigh, challenge.AlgoPBKDF2SHA256, 1000},
		{"unknown-scrypt", "scrypt", 8, challenge.RiskHigh, challenge.AlgoPBKDF2SHA256, 12},
		{"unknown-empty", "", 8, challenge.RiskHigh, challenge.AlgoPBKDF2SHA256, 12},
		{"cased-sha-256", "SHA-256", 8, challenge.RiskLow, challenge.AlgoSHA256, 8},
		{"cased-pbkdf2", "  PBKDF2-SHA256  ", 8, challenge.RiskLow, challenge.AlgoPBKDF2SHA256, 8},
		{"argon2id", "argon2id", 8, challenge.RiskLow, challenge.AlgoArgon2id, 8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &challenge.Manager{Secret: []byte("pbt-secret-16bytes"), Algorithm: tc.alg, Difficulty: tc.diff, CookieName: "pbt", CookieTTL: time.Hour}
			ch, err := m.IssueChallenge("client", tc.risk, challenge.GateInvisible)
			if err != nil {
				t.Fatalf("issue: %v", err)
			}
			if ch.Algorithm != tc.wantAlgo {
				t.Fatalf("algorithm=%s want %s", ch.Algorithm, tc.wantAlgo)
			}
			if ch.Difficulty != tc.wantDiff {
				t.Fatalf("difficulty=%d want %d", ch.Difficulty, tc.wantDiff)
			}
			if ch.MaxNumber == 0 || ch.MaxNumber > 1<<32 {
				t.Fatalf("maxnumber=%d out of bounds", ch.MaxNumber)
			}
		})
	}
}

func TestClearanceCookieIndependentOracle(t *testing.T) {
	m := &challenge.Manager{Secret: []byte("cookie-secret-16!"), CookieName: "rg_clear", CookieTTL: time.Hour}
	bindID := "203.0.113.1"
	ray := "ray-abc"

	c := m.ClearanceCookie(bindID, ray, true)
	if c.Name != "rg_clear" {
		t.Fatalf("cookie name=%s want rg_clear", c.Name)
	}
	if c.Path != "/" {
		t.Fatalf("cookie path=%s want /", c.Path)
	}
	if !c.HttpOnly {
		t.Fatal("cookie must be httponly")
	}
	if !c.Secure {
		t.Fatal("cookie must be secure")
	}

	parts := strings.Split(c.Value, ".")
	if len(parts) != 2 {
		t.Fatalf("cookie value has %d parts, want 2", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	want := refCookieMAC(m.Secret, string(payload))
	if parts[1] != want {
		t.Fatalf("cookie mac mismatch: got %s want %s", parts[1], want)
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(c)
	if !m.HasClearance(r, bindID) {
		t.Fatal("expected clearance for valid cookie")
	}
}

func TestAdversarialHasClearance(t *testing.T) {
	m := &challenge.Manager{Secret: []byte("cookie-secret-16!"), CookieName: "rg_clear", CookieTTL: time.Hour}
	other := &challenge.Manager{Secret: []byte("other-secret-16!"), CookieName: "rg_clear", CookieTTL: time.Hour}
	bindID := "203.0.113.1"
	ray := "ray-abc"
	valid := m.ClearanceCookie(bindID, ray, true)

	type tc struct {
		name   string
		cookie *http.Cookie
		mgr    *challenge.Manager
		bind   string
		path   string
		want   bool
	}

	cases := []tc{
		{"valid", valid, m, bindID, "/", true},
		{"wrong-bind", valid, m, "203.0.113.2", "/", false},
		{"wrong-secret", valid, other, bindID, "/", false},
		{"missing-cookie", nil, m, bindID, "/", false},
		{"wrong-name", &http.Cookie{Name: "other", Value: valid.Value}, m, bindID, "/", false},
		{"empty-value", &http.Cookie{Name: "rg_clear", Value: ""}, m, bindID, "/", false},
		{"forged-random", &http.Cookie{Name: "rg_clear", Value: "forged.value"}, m, bindID, "/", false},
		{"forged-no-dot", &http.Cookie{Name: "rg_clear", Value: base64.RawURLEncoding.EncodeToString([]byte("x"))}, m, bindID, "/", false},
	}

	// Expired but otherwise well-formed cookie.
	expiredPayload := fmt.Sprintf("%s|%d|%s", bindID, time.Now().Add(-time.Hour).Unix(), ray)
	expiredValue := base64.RawURLEncoding.EncodeToString([]byte(expiredPayload)) + "." + refCookieMAC(m.Secret, expiredPayload)
	cases = append(cases, tc{"expired", &http.Cookie{Name: "rg_clear", Value: expiredValue}, m, bindID, "/", false})

	// Tampered payload with the original MAC (replay of a valid MAC on forged data).
	tamperedPayload := fmt.Sprintf("%s|%d|%s", "other-bind", time.Now().Add(time.Hour).Unix(), ray)
	tamperedValue := base64.RawURLEncoding.EncodeToString([]byte(tamperedPayload)) + "." + strings.Split(valid.Value, ".")[1]
	cases = append(cases, tc{"tampered-mac", &http.Cookie{Name: "rg_clear", Value: tamperedValue}, m, bindID, "/", false})

	// Negative TTL cookie, issued with a past Expires.
	neg := &challenge.Manager{Secret: []byte("cookie-secret-16!"), CookieName: "rg_clear", CookieTTL: -time.Hour}
	negCookie := neg.ClearanceCookie(bindID, ray, false)
	cases = append(cases, tc{"negative-ttl", negCookie, m, bindID, "/", false})

	// Path bypass: the server must not restrict clearance by request path.
	for _, path := range []string{"/", "/admin", "/api/private", "/.well-known", "/foo/bar?x=1"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.AddCookie(valid)
		if !m.HasClearance(r, bindID) {
			t.Fatalf("path bypass false negative for %s", path)
		}
	}
	// No cookie on a protected path should fail.
	r := httptest.NewRequest(http.MethodGet, "/admin", nil)
	if m.HasClearance(r, bindID) {
		t.Fatal("missing cookie should not grant clearance")
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.cookie != nil {
				r.AddCookie(tc.cookie)
			}
			if got := tc.mgr.HasClearance(r, tc.bind); got != tc.want {
				t.Fatalf("HasClearance=%v want %v", got, tc.want)
			}
		})
	}
}
