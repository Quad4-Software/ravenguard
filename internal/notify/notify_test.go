// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package notify_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/notify"
	"github.com/Quad4-Software/ravenguard/internal/requestlog"
)

func TestNotifyDeliversSubscribedAction(t *testing.T) {
	var got atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev requestlog.Event
		if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
			t.Errorf("decode: %v", err)
		}
		if ev.Action != requestlog.ActionBlock {
			t.Errorf("action=%q", ev.Action)
		}
		got.Add(1)
	}))
	defer srv.Close()

	n := notify.New(srv.URL, []string{requestlog.ActionBlock}, time.Second)
	defer n.Close()
	n.Notify(requestlog.Event{Action: requestlog.ActionChallenge, Ray: "c"})
	n.Notify(requestlog.Event{Action: requestlog.ActionBlock, Ray: "b1"})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got.Load() == 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("deliveries=%d, want 1", got.Load())
}

func TestNotifyNilURL(t *testing.T) {
	if notify.New("", nil, time.Second) != nil {
		t.Fatal("empty url should return nil")
	}
}

func TestNotifyDropsWhenFull(t *testing.T) {
	// A webhook that never answers: the queue fills and Notify must not block.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer srv.Close()

	n := notify.New(srv.URL, nil, time.Second)
	defer n.Close()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 300; i++ {
			n.Notify(requestlog.Event{Action: requestlog.ActionBlock, Ray: "x"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Notify blocked on a full queue")
	}
}
