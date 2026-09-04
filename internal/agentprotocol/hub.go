// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package agentprotocol

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

// TokenLookup resolves an enrollment token hash to a proxy record.
type TokenLookup interface {
	LookupToken(tokenHash string) (proxyID string, fingerprint string, name string, universal bool, err error)
	BindFingerprint(proxyID, fingerprint, name, hostname string) error
	TouchProxy(proxyID string, listenHTTP, listenHTTPS, listenQUIC string) error
	DesiredRevision(proxyID string) (int64, error)
	DesiredState(proxyID string) (DesiredState, error)
}

// Session is a live authenticated agent connection.
type Session struct {
	ProxyID     string
	Fingerprint string
	Name        string
	Version     string
	conn        *websocket.Conn
	mu          sync.Mutex
	pending     map[string]chan Envelope
	closed      chan struct{}
}

func (s *Session) Close(msg string) {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	_ = s.conn.Close(websocket.StatusNormalClosure, msg)
}

func (s *Session) Call(ctx context.Context, op string, payload any) (Envelope, error) {
	id, err := NewID()
	if err != nil {
		return Envelope{}, err
	}
	var raw json.RawMessage
	if payload != nil {
		raw, err = json.Marshal(payload)
		if err != nil {
			return Envelope{}, err
		}
	}
	ch := make(chan Envelope, 1)
	s.mu.Lock()
	if s.pending == nil {
		s.pending = make(map[string]chan Envelope)
	}
	s.pending[id] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
	}()

	env := Envelope{V: ProtocolVersion, ID: id, Op: op, Payload: raw}
	writeCtx, cancel := context.WithTimeout(ctx, time.Duration(DefaultRPCTimeout)*time.Second)
	defer cancel()
	if err := wsjson.Write(writeCtx, s.conn, env); err != nil {
		return Envelope{}, err
	}
	select {
	case <-ctx.Done():
		return Envelope{}, ctx.Err()
	case <-s.closed:
		return Envelope{}, fmt.Errorf("session closed")
	case resp := <-ch:
		if resp.OK != nil && !*resp.OK {
			if resp.Error == "" {
				return resp, fmt.Errorf("rpc failed")
			}
			return resp, fmt.Errorf("%s", resp.Error)
		}
		return resp, nil
	case <-time.After(time.Duration(DefaultRPCTimeout) * time.Second):
		return Envelope{}, fmt.Errorf("rpc timeout")
	}
}

func (s *Session) deliver(env Envelope) {
	s.mu.Lock()
	ch := s.pending[env.ID]
	s.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- env:
	default:
	}
}

// Registry tracks online proxy sessions.
type Registry struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

func NewRegistry() *Registry {
	return &Registry{sessions: make(map[string]*Session)}
}

func (r *Registry) Put(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.sessions[s.ProxyID]; ok && old != s {
		old.Close("replaced")
	}
	r.sessions[s.ProxyID] = s
}

func (r *Registry) Remove(proxyID string, s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.sessions[proxyID]; ok && cur == s {
		delete(r.sessions, proxyID)
	}
}

func (r *Registry) Get(proxyID string) (*Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sessions[proxyID]
	return s, ok
}

func (r *Registry) ListOnline() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.sessions))
	for id := range r.sessions {
		out = append(out, id)
	}
	return out
}

func (r *Registry) Call(ctx context.Context, proxyID, op string, payload any) (Envelope, error) {
	s, ok := r.Get(proxyID)
	if !ok {
		return Envelope{}, fmt.Errorf("proxy offline")
	}
	return s.Call(ctx, op, payload)
}

func (r *Registry) FanOut(ctx context.Context, proxyIDs []string, op string, payload any) map[string]error {
	out := make(map[string]error, len(proxyIDs))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, id := range proxyIDs {
		wg.Add(1)
		go func(proxyID string) {
			defer wg.Done()
			_, err := r.Call(ctx, proxyID, op, payload)
			mu.Lock()
			out[proxyID] = err
			mu.Unlock()
		}(id)
	}
	wg.Wait()
	return out
}

// Hub accepts agent WebSocket connections.
type Hub struct {
	Keys     KeyPair
	Lookup   TokenLookup
	Registry *Registry
	OnReady  func(ctx context.Context, s *Session)

	limitMu sync.Mutex
	limit   map[string][]time.Time
}

const connectRateLimit = 20
const connectRateWindow = time.Minute

func (h *Hub) allowConnect(ip string) bool {
	if ip == "" {
		ip = "unknown"
	}
	now := time.Now()
	h.limitMu.Lock()
	defer h.limitMu.Unlock()
	if h.limit == nil {
		h.limit = make(map[string][]time.Time)
	}
	cut := now.Add(-connectRateWindow)
	kept := h.limit[ip][:0]
	for _, t := range h.limit[ip] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= connectRateLimit {
		h.limit[ip] = kept
		return false
	}
	h.limit[ip] = append(kept, now)
	return true
}

func (h *Hub) HandleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = r.RemoteAddr
	}
	if !h.allowConnect(ip) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	token := strings.TrimSpace(r.Header.Get(HeaderToken))
	if token == "" {
		authz := r.Header.Get("Authorization")
		if len(authz) > 7 && strings.EqualFold(authz[:7], "bearer ") {
			token = strings.TrimSpace(authz[7:])
		}
	}
	if token == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}
	proxyID, fp, name, universal, err := h.Lookup.LookupToken(HashToken(token))
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	agentVer := strings.TrimSpace(r.Header.Get(HeaderAgentVer))

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	conn.SetReadLimit(MaxFrameBytes)

	ctx := r.Context()
	nonce, err := RandomNonce()
	if err != nil {
		_ = conn.Close(websocket.StatusInternalError, "nonce")
		return
	}
	ts := time.Now().Unix()
	tokenHash := HashToken(token)
	chal := ChallengePayload{
		Nonce:     nonce,
		Timestamp: ts,
		Signature: SignChallenge(h.Keys.Private, tokenHash, nonce, ts),
	}
	chalRaw, _ := json.Marshal(chal)
	chalID, _ := NewID()
	if err := wsjson.Write(ctx, conn, Envelope{V: ProtocolVersion, ID: chalID, Op: OpAuthChallenge, Payload: chalRaw}); err != nil {
		_ = conn.Close(websocket.StatusInternalError, "challenge")
		return
	}

	var resp Envelope
	readCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	err = wsjson.Read(readCtx, conn, &resp)
	cancel()
	if err != nil || resp.Op != OpAuthFingerprint {
		_ = conn.Close(websocket.StatusPolicyViolation, "expected fingerprint")
		return
	}
	var fpPayload FingerprintPayload
	if err := json.Unmarshal(resp.Payload, &fpPayload); err != nil || fpPayload.Fingerprint == "" {
		_ = conn.Close(websocket.StatusPolicyViolation, "bad fingerprint")
		return
	}
	if len(fpPayload.Fingerprint) < 32 || len(fpPayload.Fingerprint) > 128 {
		_ = conn.Close(websocket.StatusPolicyViolation, "bad fingerprint")
		return
	}
	if !universal && fp != "" && fp != fpPayload.Fingerprint {
		_ = conn.Close(websocket.StatusPolicyViolation, "fingerprint mismatch")
		return
	}
	displayName := fpPayload.Name
	if displayName == "" {
		displayName = name
	}
	if err := h.Lookup.BindFingerprint(proxyID, fpPayload.Fingerprint, displayName, fpPayload.Hostname); err != nil {
		slog.Warn("agent bind fingerprint", "proxy_id", proxyID, "err", err)
		_ = conn.Close(websocket.StatusPolicyViolation, "bind failed")
		return
	}
	_ = h.Lookup.TouchProxy(proxyID, fpPayload.ListenHTTP, fpPayload.ListenHTTPS, fpPayload.ListenQUIC)

	rev, _ := h.Lookup.DesiredRevision(proxyID)
	okRaw, _ := json.Marshal(AuthOKPayload{ProxyID: proxyID, Revision: rev})
	ok := okTrue()
	_ = wsjson.Write(ctx, conn, Envelope{V: ProtocolVersion, ID: resp.ID, Op: OpAuthFingerprint, OK: ok, Payload: okRaw})

	sess := &Session{
		ProxyID:     proxyID,
		Fingerprint: fpPayload.Fingerprint,
		Name:        displayName,
		Version:     firstNonEmpty(agentVer, fpPayload.Version),
		conn:        conn,
		pending:     make(map[string]chan Envelope),
		closed:      make(chan struct{}),
	}
	h.Registry.Put(sess)
	slog.Info("agent connected", "proxy_id", proxyID, "name", displayName, "version", sess.Version)

	if h.OnReady != nil {
		go h.OnReady(context.Background(), sess)
	}

	defer func() {
		h.Registry.Remove(proxyID, sess)
		sess.Close("bye")
		slog.Info("agent disconnected", "proxy_id", proxyID)
	}()

	for {
		var env Envelope
		if err := wsjson.Read(ctx, conn, &env); err != nil {
			return
		}
		if env.OK != nil {
			sess.deliver(env)
			continue
		}
		if env.Op == OpHeartbeat {
			ok := okTrue()
			_ = wsjson.Write(ctx, conn, Envelope{V: ProtocolVersion, ID: env.ID, Op: OpHeartbeat, OK: ok})
			continue
		}
		// Agents must not initiate control ops toward the hub.
		f := false
		_ = wsjson.Write(ctx, conn, Envelope{V: ProtocolVersion, ID: env.ID, Op: env.Op, OK: &f, Error: "unsupported"})
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
