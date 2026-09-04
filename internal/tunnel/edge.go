// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package tunnel

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// EdgeAcceptConfig configures the edge tunnel accept endpoint.
type EdgeAcceptConfig struct {
	Registry   *Registry
	TicketKey  []byte
	EdgeID     string
	RequireTLS bool
}

// HandleConnect upgrades a WebSocket and registers a connector session.
func (c EdgeAcceptConfig) HandleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if c.RequireTLS && r.TLS == nil {
		http.Error(w, "tls required", http.StatusBadRequest)
		return
	}
	ticket := strings.TrimSpace(r.Header.Get(HeaderTicket))
	t, err := VerifyTicket(c.TicketKey, ticket, c.EdgeID)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
		Subprotocols:    []string{"rg-tunnel"},
	})
	if err != nil {
		return
	}
	nc := websocket.NetConn(r.Context(), conn, websocket.MessageBinary)
	sess, err := newSession(t.ConnectorID, nc, true)
	if err != nil {
		_ = conn.Close(websocket.StatusInternalError, "yamux")
		return
	}
	c.Registry.Replace(t.ConnectorID, sess)
	slog.Info("tunnel connector online", "connector_id", t.ConnectorID)
	<-sess.sess.CloseChan()
	c.Registry.Remove(t.ConnectorID, sess)
	slog.Info("tunnel connector offline", "connector_id", t.ConnectorID)
}

// Allowlist maps upstream_id to local origin URL (http://127.0.0.1:port).
type Allowlist struct {
	mu   sync.RWMutex
	byID map[string]string
}

func NewAllowlist(m map[string]string) *Allowlist {
	cp := make(map[string]string, len(m))
	for k, v := range m {
		cp[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return &Allowlist{byID: cp}
}

func (a *Allowlist) Replace(m map[string]string) {
	cp := make(map[string]string, len(m))
	for k, v := range m {
		cp[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	a.mu.Lock()
	a.byID = cp
	a.mu.Unlock()
}

func (a *Allowlist) Lookup(upstreamID string) (string, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	u, ok := a.byID[upstreamID]
	return u, ok && u != ""
}

// ConnectorDialer maintains an outbound tunnel to an edge.
type ConnectorDialer struct {
	EdgeURL   string
	Ticket    string
	Allowlist *Allowlist
	DialLocal func(ctx context.Context, originURL string) (net.Conn, error)
}

func (d *ConnectorDialer) Run(ctx context.Context) error {
	if d.DialLocal == nil {
		d.DialLocal = dialHTTPOrigin
	}
	backoff := time.Second
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := d.connectOnce(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		slog.Warn("tunnel dialer disconnected", "err", err, "edge", redactURL(d.EdgeURL))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (d *ConnectorDialer) connectOnce(ctx context.Context) error {
	hdr := http.Header{}
	hdr.Set(HeaderTicket, d.Ticket)
	dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	conn, resp, err := websocket.Dial(dialCtx, d.EdgeURL, &websocket.DialOptions{
		HTTPHeader:   hdr,
		Subprotocols: []string{"rg-tunnel"},
	})
	cancel()
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return err
	}
	nc := websocket.NetConn(ctx, conn, websocket.MessageBinary)
	sess, err := newSession("local", nc, false)
	if err != nil {
		_ = conn.Close(websocket.StatusInternalError, "yamux")
		return err
	}
	defer func() { _ = sess.Close() }()
	slog.Info("tunnel connected to edge", "edge", redactURL(d.EdgeURL))
	for {
		stream, upstreamID, err := sess.AcceptStream()
		if err != nil {
			return err
		}
		origin, ok := d.Allowlist.Lookup(upstreamID)
		if !ok {
			_ = stream.Close()
			continue
		}
		go d.handleStream(ctx, stream, origin)
	}
}

func (d *ConnectorDialer) handleStream(ctx context.Context, stream net.Conn, originURL string) {
	defer func() { _ = stream.Close() }()
	local, err := d.DialLocal(ctx, originURL)
	if err != nil {
		return
	}
	defer func() { _ = local.Close() }()
	Pipe(stream, local)
}

func dialHTTPOrigin(ctx context.Context, originURL string) (net.Conn, error) {
	// originURL is http://host:port or https://host:port — dial TCP host:port only.
	u := originURL
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimPrefix(u, "ws://")
	u = strings.TrimPrefix(u, "wss://")
	host := u
	if before, _, ok := strings.Cut(u, "/"); ok {
		host = before
	}
	if host == "" {
		return nil, fmt.Errorf("empty origin host")
	}
	if !strings.Contains(host, ":") {
		if strings.HasPrefix(originURL, "https://") || strings.HasPrefix(originURL, "wss://") {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", host)
}

func redactURL(raw string) string {
	if i := strings.Index(raw, "://"); i >= 0 {
		rest := raw[i+3:]
		if before, _, ok := strings.Cut(rest, "/"); ok {
			return raw[:i+3] + before
		}
		return raw[:i+3] + rest
	}
	return "[edge]"
}
