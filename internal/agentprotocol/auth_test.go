// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package agentprotocol

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"
)

func TestSignVerifyChallenge(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := RandomNonce()
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Now().Unix()
	token := "rgpt_test"
	sig := SignChallenge(kp.Private, HashToken(token), nonce, ts)
	if err := VerifyChallenge(kp.Public, HashToken(token), nonce, ts, sig); err != nil {
		t.Fatal(err)
	}
	badPub, _, _ := ed25519.GenerateKey(nil)
	if err := VerifyChallenge(badPub, HashToken(token), nonce, ts, sig); err == nil {
		t.Fatal("expected verify failure")
	}
}

func TestHashTokenStable(t *testing.T) {
	a := HashToken("abc")
	b := HashToken("abc")
	if a != b || a == "" {
		t.Fatalf("hash mismatch %q %q", a, b)
	}
	if HashToken("abd") == a {
		t.Fatal("expected different hash")
	}
}

func TestDesiredStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	state := DesiredState{Revision: 3, SafeConfig: json.RawMessage(`{"x":1}`)}
	if err := SaveDesiredState(dir, state); err != nil {
		t.Fatal(err)
	}
	got, err := LoadDesiredState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Revision != 3 {
		t.Fatalf("revision %d", got.Revision)
	}
}

func TestEnvelopeJSON(t *testing.T) {
	ok := true
	env := Envelope{V: 1, ID: "1", Op: OpHeartbeat, OK: &ok}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var back Envelope
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.Op != OpHeartbeat || back.OK == nil || !*back.OK {
		t.Fatalf("%+v", back)
	}
}

func TestKeyPairPersist(t *testing.T) {
	dir := t.TempDir()
	kp1, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	kp2, err := LoadOrCreateKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	if kp1.PublicKeyBase64() != kp2.PublicKeyBase64() {
		t.Fatal("keypair not stable")
	}
	_ = context.Background()
}
