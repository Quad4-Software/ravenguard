// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package store

import (
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/agentprotocol"
)

func TestBindFingerprintRejectsReuseAndMismatch(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	a, _, err := st.CreateProxy("a", nil, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := st.CreateProxy("b", nil, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.BindFingerprint(a.ID, "fp-aaaa", "a", "host-a"); err != nil {
		t.Fatal(err)
	}
	if err := st.BindFingerprint(b.ID, "fp-aaaa", "b", "host-b"); err == nil {
		t.Fatal("expected fingerprint reuse rejection")
	}
	if err := st.BindFingerprint(a.ID, "fp-bbbb", "a", "host-a"); err == nil {
		t.Fatal("expected mismatch rejection after bind")
	}
	if err := st.BindFingerprint(a.ID, "fp-aaaa", "a2", "host-a"); err != nil {
		t.Fatal(err)
	}
	_ = agentprotocol.HashToken("x")
}
