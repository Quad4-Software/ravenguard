// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package tunnel_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/tunnel"
	"github.com/hashicorp/yamux"
)

func TestTicketRoundTrip(t *testing.T) {
	secret := []byte("test-secret-32-bytes-long!!!!!!")
	raw, err := tunnel.IssueTicket(secret, "conn-1", "edge-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "conn-1") {
		t.Fatal("ticket should be opaque encoding")
	}
	got, err := tunnel.VerifyTicket(secret, raw, "edge-a")
	if err != nil {
		t.Fatal(err)
	}
	if got.ConnectorID != "conn-1" {
		t.Fatalf("got %+v", got)
	}
	if _, err := tunnel.VerifyTicket(secret, raw, "edge-b"); err == nil {
		t.Fatal("expected edge mismatch")
	}
	if _, err := tunnel.VerifyTicket([]byte("other"), raw, ""); err == nil {
		t.Fatal("expected bad sig")
	}
}

func TestRG1Header(t *testing.T) {
	var buf bytes.Buffer
	if err := tunnel.WriteOpenHeader(&buf, "web"); err != nil {
		t.Fatal(err)
	}
	id, err := tunnel.ReadOpenHeader(&buf)
	if err != nil || id != "web" {
		t.Fatalf("id=%q err=%v", id, err)
	}
	if err := tunnel.WriteOpenHeader(&buf, "bad\nid"); err == nil {
		t.Fatal("expected reject")
	}
}

func TestRegistryReplaceRace(t *testing.T) {
	reg := tunnel.NewRegistry()
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			c1, c2 := net.Pipe()
			s, err := yamux.Client(c1, nil)
			if err != nil {
				_ = c1.Close()
				_ = c2.Close()
				return
			}
			_ = c2.Close()
			// Use Dial path with offline - just stress Get/Remove
			_ = s.Close()
			_, _ = reg.Get("c")
			reg.Remove("c", nil)
		})
	}
	wg.Wait()
}

func TestYamuxStreamRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	server, err := yamux.Server(a, nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := yamux.Client(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close(); _ = client.Close() }()

	done := make(chan string, 1)
	go func() {
		st, err := server.Accept()
		if err != nil {
			done <- err.Error()
			return
		}
		id, err := tunnel.ReadOpenHeader(st)
		if err != nil {
			done <- err.Error()
			return
		}
		_, _ = io.WriteString(st, "pong")
		_ = st.Close()
		done <- id
	}()

	st, err := client.Open()
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnel.WriteOpenHeader(st, "origin-1"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	_, _ = io.ReadFull(st, buf)
	_ = st.Close()
	select {
	case id := <-done:
		if id != "origin-1" {
			t.Fatalf("id=%q", id)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
	if string(buf) != "pong" {
		t.Fatalf("buf=%q", buf)
	}
}

func TestAllowlistSSRF(t *testing.T) {
	al := tunnel.NewAllowlist(map[string]string{"web": "http://127.0.0.1:8080"})
	if _, ok := al.Lookup("web"); !ok {
		t.Fatal("missing")
	}
	if _, ok := al.Lookup("evil"); ok {
		t.Fatal("should miss")
	}
	al.Replace(map[string]string{})
	if _, ok := al.Lookup("web"); ok {
		t.Fatal("cleared")
	}
}

func TestEdgeRejectsBadTicket(t *testing.T) {
	reg := tunnel.NewRegistry()
	h := tunnel.EdgeAcceptConfig{Registry: reg, TicketKey: []byte("secret")}.HandleConnect
	req := httptest.NewRequest(http.MethodGet, tunnel.ConnectPath, nil)
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("code=%d", rr.Code)
	}
}

func TestDialOffline(t *testing.T) {
	reg := tunnel.NewRegistry()
	_, err := reg.Dial("missing", "web")
	if err == nil {
		t.Fatal("expected offline")
	}
}

func TestLeakageTicketNotInLogs(t *testing.T) {
	secret := []byte("secret-key-material-here!!!!")
	raw, err := tunnel.IssueTicket(secret, "c1", "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// IssueTicket returns opaque token; connector_id must not appear plainly.
	if strings.Contains(raw, `"connector_id"`) {
		t.Fatal("ticket leaked json")
	}
	_ = context.Background()
}
