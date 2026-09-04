// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package store_test

import (
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/admin/store"
	"github.com/Quad4-Software/ravenguard/internal/agentprotocol"
)

func TestThreatLedgerInsertPullAdmin(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	now := time.Now()
	stored, rev, err := st.InsertThreatEntries("proxy-a", []agentprotocol.ThreatEntry{
		{KeyType: agentprotocol.ThreatKeyBind, Key: "bind-secret-key", TTLSeconds: 600, Reason: "scraper", CreatedAtUnix: now.Unix()},
		{KeyType: agentprotocol.ThreatKeyUA, Key: "curl/", TTLSeconds: 300, Reason: "bot"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 2 || rev < 2 {
		t.Fatalf("stored=%d rev=%d", len(stored), rev)
	}
	entries, rev2, err := st.ListThreatSince(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if rev2 != rev || len(entries) != 2 {
		t.Fatalf("pull len=%d rev=%d", len(entries), rev2)
	}
	admin, _, err := st.ListThreatAdmin(50)
	if err != nil {
		t.Fatal(err)
	}
	if len(admin) != 2 {
		t.Fatalf("admin %d", len(admin))
	}
	for _, row := range admin {
		kr, _ := row["key_redacted"].(string)
		if kr == "bind-secret-key" {
			t.Fatal("full bind key in admin listing")
		}
		if _, ok := row["key_material"]; ok {
			t.Fatal("key_material exposed to admin")
		}
	}
}

func TestThreatLedgerRace(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	done := make(chan struct{})
	for i := range 8 {
		go func(n int) {
			for range 40 {
				_, _, _ = st.InsertThreatEntries("p", []agentprotocol.ThreatEntry{{
					KeyType: agentprotocol.ThreatKeyBind, Key: "k", TTLSeconds: 60, Reason: "r",
				}})
				_, _, _ = st.ListThreatSince(0, 20)
				_, _ = st.SweepThreatEntries()
			}
			done <- struct{}{}
		}(i)
	}
	for range 8 {
		<-done
	}
}
