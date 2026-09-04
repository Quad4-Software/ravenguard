// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package agentprotocol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRegistryOnlineLifecycle(t *testing.T) {
	reg := NewRegistry()
	s := &Session{ProxyID: "p1", closed: make(chan struct{}), pending: map[string]chan Envelope{}}
	reg.Put(s)
	if ids := reg.ListOnline(); len(ids) != 1 || ids[0] != "p1" {
		t.Fatalf("%v", ids)
	}
	got, ok := reg.Get("p1")
	if !ok || got != s {
		t.Fatal("get")
	}
	reg.Remove("p1", s)
	if _, ok := reg.Get("p1"); ok {
		t.Fatal("expected removed")
	}
	_, err := reg.Call(context.Background(), "missing", OpStatus, nil)
	if err == nil {
		t.Fatal("expected offline")
	}
	out := reg.FanOut(context.Background(), []string{"missing"}, OpStatus, nil)
	if out["missing"] == nil {
		t.Fatal("expected fanout error")
	}
}

func TestHubAllowConnectRateLimit(t *testing.T) {
	h := &Hub{}
	for i := range connectRateLimit {
		if !h.allowConnect("1.2.3.4") {
			t.Fatalf("unexpected deny at %d", i)
		}
	}
	if h.allowConnect("1.2.3.4") {
		t.Fatal("expected rate limit")
	}
	if !h.allowConnect("9.9.9.9") {
		t.Fatal("other IP should be allowed")
	}
}

func TestHubHandleConnectRejects(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	h := &Hub{Keys: kp, Lookup: stubLookup{}, Registry: NewRegistry()}

	req := httptest.NewRequest(http.MethodPost, ConnectPath, nil)
	rr := httptest.NewRecorder()
	h.HandleConnect(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("method: %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodGet, ConnectPath, nil)
	rr = httptest.NewRecorder()
	h.HandleConnect(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("missing token: %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodGet, ConnectPath, nil)
	req.Header.Set(HeaderToken, "bad")
	rr = httptest.NewRecorder()
	h.HandleConnect(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", rr.Code)
	}
}

func TestFirstNonEmptyAndOKHelpers(t *testing.T) {
	if firstNonEmpty("", " a ", "b") != " a " {
		t.Fatal("firstNonEmpty")
	}
	if !*okTrue() || *okFalse() {
		t.Fatal("ok helpers")
	}
}

func TestSessionDeliver(t *testing.T) {
	s := &Session{pending: map[string]chan Envelope{}, closed: make(chan struct{})}
	ch := make(chan Envelope, 1)
	s.pending["abc"] = ch
	s.deliver(Envelope{ID: "abc", Op: OpHeartbeat})
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("deliver timeout")
	}
	s.deliver(Envelope{ID: "missing"})
}

type stubLookup struct{}

func (stubLookup) LookupToken(tokenHash string) (string, string, string, bool, error) {
	return "", "", "", false, ErrNotFoundish
}

func (stubLookup) BindFingerprint(proxyID, fingerprint, name, hostname string) error { return nil }
func (stubLookup) TouchProxy(proxyID string, listenHTTP, listenHTTPS, listenQUIC, agentVersion string) error {
	return nil
}
func (stubLookup) DesiredRevision(proxyID string) (int64, error) { return 0, nil }
func (stubLookup) DesiredState(proxyID string) (DesiredState, error) {
	return DesiredState{}, nil
}

type notFoundErr string

func (e notFoundErr) Error() string { return string(e) }

const ErrNotFoundish = notFoundErr("not found")
