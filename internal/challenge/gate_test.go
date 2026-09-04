// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package challenge_test

import (
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/challenge"
)

func TestSelectGate(t *testing.T) {
	cases := []struct {
		mode string
		risk challenge.RiskLevel
		want string
	}{
		{"detect", challenge.RiskLow, challenge.GateInvisible},
		{"detect", challenge.RiskElevated, challenge.GateInvisible},
		{"detect", challenge.RiskHigh, challenge.GateInteractive},
		{"always", challenge.RiskLow, challenge.GateInvisible},
		{"always", challenge.RiskHigh, challenge.GateInteractive},
		{"attack", challenge.RiskLow, challenge.GateInteractive},
		{"attack", challenge.RiskElevated, challenge.GateInteractive},
		{"attack", challenge.RiskHigh, challenge.GateInteractive},
	}
	for _, tc := range cases {
		got := challenge.SelectGate(tc.mode, tc.risk)
		if got != tc.want {
			t.Fatalf("SelectGate(%q,%v)=%q want %q", tc.mode, tc.risk, got, tc.want)
		}
	}
}

func TestResolveGate(t *testing.T) {
	if g := challenge.ResolveGate("attack", challenge.RiskLow, "", false); g != challenge.GateInteractive {
		t.Fatalf("attack cold=%q", g)
	}
	if g := challenge.ResolveGate("always", challenge.RiskLow, "", false); g != challenge.GateInvisible {
		t.Fatalf("always cold=%q", g)
	}
	if g := challenge.ResolveGate("always", challenge.RiskLow, "", true); g != challenge.GateInteractive {
		t.Fatalf("captcha forces interactive got=%q", g)
	}
	if g := challenge.ResolveGate("detect", challenge.RiskLow, challenge.GateInteractive, false); g != challenge.GateInteractive {
		t.Fatalf("prior interactive=%q", g)
	}
}

func TestFloorRiskForMode(t *testing.T) {
	if challenge.FloorRiskForMode("attack", challenge.RiskLow) != challenge.RiskElevated {
		t.Fatal("attack should floor to elevated")
	}
	if challenge.FloorRiskForMode("detect", challenge.RiskLow) != challenge.RiskLow {
		t.Fatal("detect should keep low")
	}
}

func TestIssueChallengeGateSigned(t *testing.T) {
	m := &challenge.Manager{
		Secret:     []byte("fixture-secret-16!"),
		Difficulty: 8,
		Algorithm:  "sha256",
		CookieName: "rg_clear",
	}
	ch, err := m.IssueChallenge("client-a", challenge.RiskLow, challenge.GateInvisible)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Gate != challenge.GateInvisible {
		t.Fatalf("gate=%q", ch.Gate)
	}
	sol, err := challenge.SolveChallenge(ch)
	if err != nil {
		t.Fatal(err)
	}
	payload := challenge.Payload{
		V: ch.V, Algorithm: ch.Algorithm, Challenge: ch.Challenge, Salt: ch.Salt,
		Difficulty: ch.Difficulty, MaxNumber: ch.MaxNumber, Expires: ch.Expires,
		Bind: ch.Bind, Gate: ch.Gate, Params: ch.Params, Signature: ch.Signature,
		Solution: formatUint(sol),
		Env:      challenge.EnvAttestation{Interacted: false, SolveMs: 100},
	}
	raw, err := challenge.EncodePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.VerifyPayload(raw, "client-a")
	if err != nil {
		t.Fatal(err)
	}
	if got.Gate != challenge.GateInvisible {
		t.Fatalf("verified gate=%q", got.Gate)
	}
}

func TestRememberChallenge(t *testing.T) {
	m := &challenge.Manager{Secret: []byte("fixture-secret-16!")}
	m.RememberChallenge("x", challenge.RiskHigh, challenge.GateInteractive)
	risk, gate := m.TakeChallenge("x")
	if risk != challenge.RiskHigh || gate != challenge.GateInteractive {
		t.Fatalf("risk=%v gate=%q", risk, gate)
	}
}

func TestTakeChallengeMissGateEmpty(t *testing.T) {
	m := &challenge.Manager{Secret: []byte("fixture-secret-16!")}
	risk, gate := m.TakeChallenge("never-seen")
	if risk != challenge.RiskLow || gate != "" {
		t.Fatalf("miss risk=%v gate=%q want low and empty gate", risk, gate)
	}
}
