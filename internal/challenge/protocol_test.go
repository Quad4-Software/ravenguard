// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package challenge_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/challenge"
)

func TestIssueChallengeRoundTrip(t *testing.T) {
	m := &challenge.Manager{
		Secret:     []byte("fixture-secret-16!"),
		Difficulty: 8,
		Algorithm:  "sha256",
		CookieName: "rg_clear",
	}
	ch, err := m.IssueChallenge("client-a", challenge.RiskLow)
	if err != nil {
		t.Fatal(err)
	}
	if ch.V != 1 || ch.Algorithm != challenge.AlgoSHA256 {
		t.Fatalf("unexpected challenge: %+v", ch)
	}
	sol, err := challenge.SolveChallenge(ch)
	if err != nil {
		t.Fatal(err)
	}
	payload := challenge.Payload{
		V:          ch.V,
		Algorithm:  ch.Algorithm,
		Challenge:  ch.Challenge,
		Salt:       ch.Salt,
		Difficulty: ch.Difficulty,
		MaxNumber:  ch.MaxNumber,
		Expires:    ch.Expires,
		Bind:       ch.Bind,
		Params:     ch.Params,
		Signature:  ch.Signature,
		Solution:   formatUint(sol),
		Env: challenge.EnvAttestation{
			Interacted: true,
			SolveMs:    100,
		},
	}
	raw, err := challenge.EncodePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.VerifyPayload(raw, "client-a")
	if err != nil {
		t.Fatal(err)
	}
	if got.Solution != formatUint(sol) {
		t.Fatal("solution mismatch")
	}
	if _, err := m.VerifyPayload(raw, "client-a"); err == nil {
		t.Fatal("expected replay")
	}
}

func TestPBKDF2RoundTrip(t *testing.T) {
	m := &challenge.Manager{
		Secret:     []byte("fixture-secret-16!"),
		Difficulty: 4,
		Algorithm:  "pbkdf2",
		CookieName: "rg_clear",
	}
	ch, err := m.IssueChallenge("client-b", challenge.RiskElevated)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Algorithm != challenge.AlgoPBKDF2SHA256 {
		t.Fatalf("algo=%s", ch.Algorithm)
	}
	sol, err := challenge.SolveChallenge(ch)
	if err != nil {
		t.Fatal(err)
	}
	payload := challenge.Payload{
		V: ch.V, Algorithm: ch.Algorithm, Challenge: ch.Challenge, Salt: ch.Salt,
		Difficulty: ch.Difficulty, MaxNumber: ch.MaxNumber, Expires: ch.Expires,
		Bind: ch.Bind, Params: ch.Params, Signature: ch.Signature,
		Solution: formatUint(sol),
		Env:      challenge.EnvAttestation{Interacted: true, SolveMs: 200},
	}
	raw, err := challenge.EncodePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.VerifyPayload(raw, "client-b"); err != nil {
		t.Fatal(err)
	}
}

func TestAdaptiveRisk(t *testing.T) {
	m := &challenge.Manager{Secret: []byte("fixture-secret-16!"), Difficulty: 8, Algorithm: "adaptive"}
	low, _ := m.IssueChallenge("c", challenge.RiskLow)
	elev, _ := m.IssueChallenge("c", challenge.RiskElevated)
	high, _ := m.IssueChallenge("c", challenge.RiskHigh)
	if low.Algorithm != challenge.AlgoSHA256 {
		t.Fatalf("low=%s", low.Algorithm)
	}
	if elev.Algorithm != challenge.AlgoPBKDF2SHA256 {
		t.Fatalf("elev=%s", elev.Algorithm)
	}
	if high.Algorithm != challenge.AlgoPBKDF2SHA256 || high.Difficulty < elev.Difficulty {
		t.Fatalf("high=%+v elev=%+v", high, elev)
	}
}

func TestGoldenFixtures(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "challenge")
	for _, name := range []string{"sha256_v1.json", "pbkdf2_v1.json"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		var fix struct {
			Secret    string              `json:"secret"`
			Challenge challenge.Challenge `json:"challenge"`
			Solution  string              `json:"solution"`
			Payload   string              `json:"payload"`
		}
		if err := json.Unmarshal(raw, &fix); err != nil {
			t.Fatal(err)
		}
		if err := challenge.VerifySolution(fix.Challenge, mustParseUint(t, fix.Solution)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		m := &challenge.Manager{Secret: []byte(fix.Secret), Difficulty: fix.Challenge.Difficulty}
		if _, err := m.VerifyPayload(fix.Payload, fix.Challenge.Bind); err != nil {
			t.Fatalf("%s verify: %v", name, err)
		}
	}
}

func formatUint(u uint64) string {
	return strconv.FormatUint(u, 10)
}

func mustParseUint(t *testing.T, s string) uint64 {
	t.Helper()
	var u uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			t.Fatalf("bad uint %q", s)
		}
		u = u*10 + uint64(c-'0')
	}
	return u
}
