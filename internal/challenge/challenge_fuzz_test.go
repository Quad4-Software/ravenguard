// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package challenge_test

import (
	"errors"
	"strconv"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/challenge"
)

func FuzzVerifyPoW(f *testing.F) {
	m := &challenge.Manager{Secret: []byte("fuzz-secret-16char"), Difficulty: 4, CookieName: "rg_fuzz", CookieTTL: 0}
	tok, payload, err := m.Issue("fuzz-client")
	if err != nil {
		f.Fatalf("issue: %v", err)
	}
	sol, err := challenge.SolvePoW(tok.Nonce, tok.Difficulty)
	if err != nil {
		f.Fatalf("solve: %v", err)
	}
	solStr := strconv.FormatUint(sol, 10)

	f.Add(payload, solStr)
	f.Add(payload, "0")
	f.Add(payload, "not-a-number")
	f.Add("bad-token-string", "1")

	f.Fuzz(func(t *testing.T, raw, s string) {
		t.Helper()

		// Deterministic parsing: the same raw token and client ID must always
		// yield the same parsed token or error.
		parsed1, err1 := m.ParseToken(raw, "fuzz-client")
		parsed2, err2 := m.ParseToken(raw, "fuzz-client")
		if (err1 == nil) != (err2 == nil) {
			t.Fatalf("ParseToken non-deterministic: %v vs %v", err1, err2)
		}
		if err1 == nil && (parsed1.Nonce != parsed2.Nonce || parsed1.IssuedAt != parsed2.IssuedAt || parsed1.Difficulty != parsed2.Difficulty) {
			t.Fatalf("ParseToken returned different tokens for the same input")
		}
		if err1 != nil {
			return
		}

		// Differential oracle: compare VerifyPoW with an independent reference.
		want := refVerifyPoW(parsed1, s)
		got := m.VerifyPoW(parsed1, s)
		if (want == nil) != (got == nil) {
			t.Fatalf("differential mismatch for sol %q: ref=%v impl=%v", s, want, got)
		}

		// Non-numeric solutions must always be rejected.
		if _, err := strconv.ParseUint(s, 10, 64); err != nil {
			if !errors.Is(got, challenge.ErrBadSolution) {
				t.Fatalf("non-numeric solution %q: got %v", s, got)
			}
		}

		// Semantic oracle: for low difficulty tokens, find a valid solution by
		// brute force and ensure VerifyPoW accepts it.
		if parsed1.Difficulty >= 0 && parsed1.Difficulty <= 8 {
			const limit = uint64(1 << 12)
			for i := range limit {
				if refCheckPoW(parsed1.Nonce, i, parsed1.Difficulty) {
					sol := strconv.FormatUint(i, 10)
					if err := m.VerifyPoW(parsed1, sol); err != nil {
						t.Fatalf("found solution %q but VerifyPoW rejected: %v", sol, err)
					}
					break
				}
			}
		}

		// A token bound to one client must not parse for another client.
		if _, err := m.ParseToken(raw, "other-client"); err == nil {
			t.Fatal("token parsed for the wrong client ID")
		}

		// Metamorphic invariant: flipping any single bit of the raw token must
		// invalidate it.
		if len(raw) > 0 {
			b := []byte(raw)
			for i := range b {
				c := b[i]
				b[i] = c ^ 0x01
				if _, err := m.ParseToken(string(b), "fuzz-client"); err == nil {
					t.Fatalf("bit flip at position %d did not invalidate token", i)
				}
				b[i] = c
			}
		}
	})
}
