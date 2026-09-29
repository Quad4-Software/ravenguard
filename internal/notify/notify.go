// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

// Package notify fans WAF deny and challenge events out to a webhook URL,
// the same role CrowdSec notification plugins fill for external SOCs.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/requestlog"
)

// queueCap bounds buffered events; past that, new events are dropped rather
// than stalling the request path on a slow webhook.
const queueCap = 256

// Notifier posts selected requestlog events to a webhook as JSON. A single
// worker goroutine serializes sends so bursts cannot spawn connection floods.
type Notifier struct {
	url     string
	actions map[string]struct{}
	client  *http.Client
	ch      chan requestlog.Event
	done    chan struct{}
	wg      sync.WaitGroup
}

// New returns a notifier for url, or nil when url is empty. events lists the
// requestlog actions to forward; empty forwards only blocks. The worker stops
// on Close.
func New(url string, events []string, timeout time.Duration) *Notifier {
	if url == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	n := &Notifier{
		url:     url,
		actions: make(map[string]struct{}, len(events)),
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		ch:   make(chan requestlog.Event, queueCap),
		done: make(chan struct{}),
	}
	for _, a := range events {
		n.actions[a] = struct{}{}
	}
	if len(n.actions) == 0 {
		n.actions[requestlog.ActionBlock] = struct{}{}
	}
	n.wg.Add(1)
	go n.run()
	return n
}

// Notify queues e for delivery if its action is subscribed. Never blocks the
// caller; events drop silently once the queue is full.
func (n *Notifier) Notify(e requestlog.Event) {
	if n == nil {
		return
	}
	if _, ok := n.actions[e.Action]; !ok {
		return
	}
	select {
	case n.ch <- e:
	default:
	}
}

// Close stops the worker. Queued events are abandoned.
func (n *Notifier) Close() {
	if n == nil {
		return
	}
	close(n.done)
	n.wg.Wait()
}

func (n *Notifier) run() {
	defer n.wg.Done()
	for {
		select {
		case <-n.done:
			return
		case e := <-n.ch:
			n.post(e)
		}
	}
}

func (n *Notifier) post(e requestlog.Event) {
	body, err := json.Marshal(e)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), n.client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ravenguard-notify")
	resp, err := n.client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}
