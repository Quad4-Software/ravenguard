// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package challenge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestWriteGoldenFixtures regenerates testdata/challenge fixtures when
// UPDATE_CHALLENGE_FIXTURES=1 is set.
func TestWriteGoldenFixtures(t *testing.T) {
	if os.Getenv("UPDATE_CHALLENGE_FIXTURES") != "1" {
		t.Skip("set UPDATE_CHALLENGE_FIXTURES=1 to regenerate")
	}
	m := &Manager{Secret: []byte("fixture-secret-16!"), Difficulty: 8, Algorithm: "sha256"}
	ch := Challenge{
		V:          ProtocolVersion,
		Algorithm:  AlgoSHA256,
		Challenge:  "0123456789abcdef0123456789abcdef",
		Difficulty: 8,
		MaxNumber:  maxNumberFor(8),
		Expires:    4102444800, // 2100-01-01
		Bind:       "fixture-client",
		Gate:       GateInteractive,
	}
	sig, err := m.signChallenge(ch)
	if err != nil {
		t.Fatal(err)
	}
	ch.Signature = sig
	sol, err := SolveChallenge(ch)
	if err != nil {
		t.Fatal(err)
	}
	p := Payload{
		V: ch.V, Algorithm: ch.Algorithm, Challenge: ch.Challenge, Salt: ch.Salt,
		Difficulty: ch.Difficulty, MaxNumber: ch.MaxNumber, Expires: ch.Expires,
		Bind: ch.Bind, Gate: ch.Gate, Params: ch.Params, Signature: ch.Signature,
		Solution: strconv.FormatUint(sol, 10),
		Env:      EnvAttestation{Interacted: true, SolveMs: 120},
	}
	payload, err := EncodePayload(p)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join("..", "..", "testdata", "challenge")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{
		"secret":    "fixture-secret-16!",
		"challenge": ch,
		"solution":  strconv.FormatUint(sol, 10),
		"payload":   payload,
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(filepath.Join(dir, "sha256_v1.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}

	m2 := &Manager{Secret: []byte("fixture-secret-16!"), Difficulty: 4, Algorithm: "pbkdf2"}
	ch2 := Challenge{
		V:          ProtocolVersion,
		Algorithm:  AlgoPBKDF2SHA256,
		Challenge:  "fedcba9876543210fedcba9876543210",
		Salt:       "aabbccddeeff00112233445566778899",
		Difficulty: 4,
		MaxNumber:  maxNumberFor(4),
		Expires:    4102444800,
		Bind:       "fixture-client",
		Gate:       GateInteractive,
		Params:     map[string]int{"iterations": 1000},
	}
	sig2, err := m2.signChallenge(ch2)
	if err != nil {
		t.Fatal(err)
	}
	ch2.Signature = sig2
	sol2, err := SolveChallenge(ch2)
	if err != nil {
		t.Fatal(err)
	}
	p2 := Payload{
		V: ch2.V, Algorithm: ch2.Algorithm, Challenge: ch2.Challenge, Salt: ch2.Salt,
		Difficulty: ch2.Difficulty, MaxNumber: ch2.MaxNumber, Expires: ch2.Expires,
		Bind: ch2.Bind, Gate: ch2.Gate, Params: ch2.Params, Signature: ch2.Signature,
		Solution: strconv.FormatUint(sol2, 10),
		Env:      EnvAttestation{Interacted: true, SolveMs: 250},
	}
	payload2, err := EncodePayload(p2)
	if err != nil {
		t.Fatal(err)
	}
	doc2 := map[string]any{
		"secret":    "fixture-secret-16!",
		"challenge": ch2,
		"solution":  strconv.FormatUint(sol2, 10),
		"payload":   payload2,
	}
	raw2, err := json.MarshalIndent(doc2, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw2 = append(raw2, '\n')
	if err := os.WriteFile(filepath.Join(dir, "pbkdf2_v1.json"), raw2, 0o644); err != nil {
		t.Fatal(err)
	}
}
