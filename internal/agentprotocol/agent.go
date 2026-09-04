// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package agentprotocol

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

// Dispatcher handles ops received from the hub on a proxy agent.
type Dispatcher interface {
	Handle(ctx context.Context, op string, payload json.RawMessage) (any, error)
}

// AgentConfig configures the outbound agent client.
type AgentConfig struct {
	HubURL      string
	Token       string
	HubPubKey   string
	Version     string
	Name        string
	ListenHTTP  string
	ListenHTTPS string
	ListenQUIC  string
	DataDir     string
}

// Agent dials the hub and serves RPC from a local Dispatcher.
type Agent struct {
	Cfg        AgentConfig
	Dispatcher Dispatcher
	OnDesired  func(ctx context.Context, state DesiredState) error

	mu      sync.Mutex
	conn    *websocket.Conn
	pending map[string]chan Envelope
}

func (a *Agent) Run(ctx context.Context) error {
	if _, err := ParsePublicKeyBase64(a.Cfg.HubPubKey); err != nil {
		return fmt.Errorf("agent hub_pubkey: %w", err)
	}
	if strings.TrimSpace(a.Cfg.HubURL) == "" || strings.TrimSpace(a.Cfg.Token) == "" {
		return fmt.Errorf("agent hub_url and token are required")
	}
	backoff := time.Second
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := a.connectOnce(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		slog.Warn("agent disconnected", "err", err)
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

func (a *Agent) connectOnce(ctx context.Context) error {
	hubPub, err := ParsePublicKeyBase64(a.Cfg.HubPubKey)
	if err != nil {
		return err
	}

	u, err := url.Parse(strings.TrimSpace(a.Cfg.HubURL))
	if err != nil {
		return err
	}
	base := strings.TrimRight(u.String(), "/")
	connectURL := base + ConnectPath

	hdr := http.Header{}
	hdr.Set(HeaderToken, a.Cfg.Token)
	if a.Cfg.Version != "" {
		hdr.Set(HeaderAgentVer, a.Cfg.Version)
	}

	dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	conn, resp, err := websocket.Dial(dialCtx, connectURL, &websocket.DialOptions{HTTPHeader: hdr})
	cancel()
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return err
	}
	conn.SetReadLimit(MaxFrameBytes)
	a.mu.Lock()
	a.conn = conn
	a.mu.Unlock()
	defer func() {
		_ = conn.Close(websocket.StatusNormalClosure, "done")
		a.mu.Lock()
		if a.conn == conn {
			a.conn = nil
		}
		a.mu.Unlock()
	}()

	var chalEnv Envelope
	readCtx, cancelRead := context.WithTimeout(ctx, 20*time.Second)
	err = wsjson.Read(readCtx, conn, &chalEnv)
	cancelRead()
	if err != nil {
		return err
	}
	if chalEnv.Op != OpAuthChallenge {
		return fmt.Errorf("expected auth challenge")
	}
	var chal ChallengePayload
	if err := json.Unmarshal(chalEnv.Payload, &chal); err != nil {
		return err
	}
	if err := VerifyChallenge(hubPub, HashToken(a.Cfg.Token), chal.Nonce, chal.Timestamp, chal.Signature); err != nil {
		return fmt.Errorf("hub verification failed: %w", err)
	}
	fp, err := MachineFingerprint()
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	name := a.Cfg.Name
	if name == "" {
		name = host
	}
	fpPayload := FingerprintPayload{
		Fingerprint: fp,
		Name:        name,
		Hostname:    host,
		Version:     a.Cfg.Version,
		ListenHTTP:  a.Cfg.ListenHTTP,
		ListenHTTPS: a.Cfg.ListenHTTPS,
		ListenQUIC:  a.Cfg.ListenQUIC,
	}
	fpRaw, _ := json.Marshal(fpPayload)
	if err := wsjson.Write(ctx, conn, Envelope{V: ProtocolVersion, ID: chalEnv.ID, Op: OpAuthFingerprint, Payload: fpRaw}); err != nil {
		return err
	}
	var okEnv Envelope
	okCtx, cancelOK := context.WithTimeout(ctx, 20*time.Second)
	err = wsjson.Read(okCtx, conn, &okEnv)
	cancelOK()
	if err != nil {
		return err
	}
	if okEnv.OK == nil || !*okEnv.OK {
		return fmt.Errorf("auth rejected: %s", okEnv.Error)
	}
	var authOK AuthOKPayload
	_ = json.Unmarshal(okEnv.Payload, &authOK)
	slog.Info("agent connected to hub", "proxy_id", authOK.ProxyID, "revision", authOK.Revision)

	pingEvery := 25 * time.Second
	ticker := time.NewTicker(pingEvery)
	defer ticker.Stop()

	errCh := make(chan error, 1)
	go func() {
		for {
			var env Envelope
			if err := wsjson.Read(ctx, conn, &env); err != nil {
				errCh <- err
				return
			}
			if env.OK != nil {
				a.deliver(env)
				continue
			}
			go a.handleRequest(ctx, conn, env)
		}
	}()

	// Catch up threat ledger after reconnect.
	go a.pullThreats(ctx)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			return err
		case <-ticker.C:
			id, _ := NewID()
			hb, _ := json.Marshal(HeartbeatPayload{})
			_ = wsjson.Write(ctx, conn, Envelope{V: ProtocolVersion, ID: id, Op: OpHeartbeat, Payload: hb})
		}
	}
}

func (a *Agent) deliver(env Envelope) {
	a.mu.Lock()
	ch := a.pending[env.ID]
	a.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case ch <- env:
	default:
	}
}

// Call sends an agent-initiated RPC to the hub and waits for the response.
func (a *Agent) Call(ctx context.Context, op string, payload any) (Envelope, error) {
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
	a.mu.Lock()
	conn := a.conn
	if a.pending == nil {
		a.pending = make(map[string]chan Envelope)
	}
	a.pending[id] = ch
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.pending, id)
		a.mu.Unlock()
	}()
	if conn == nil {
		return Envelope{}, fmt.Errorf("agent not connected")
	}
	writeCtx, cancel := context.WithTimeout(ctx, time.Duration(DefaultRPCTimeout)*time.Second)
	defer cancel()
	if err := wsjson.Write(writeCtx, conn, Envelope{V: ProtocolVersion, ID: id, Op: op, Payload: raw}); err != nil {
		return Envelope{}, err
	}
	select {
	case <-ctx.Done():
		return Envelope{}, ctx.Err()
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

// ReportThreat sends threat.report to the hub.
func (a *Agent) ReportThreat(ctx context.Context, entries []ThreatEntry) error {
	if a == nil || len(entries) == 0 {
		return nil
	}
	_, err := a.Call(ctx, OpThreatReport, ThreatReportPayload{Entries: entries})
	return err
}

func (a *Agent) pullThreats(ctx context.Context) {
	resp, err := a.Call(ctx, OpThreatPull, ThreatPullPayload{SinceRevision: 0, Limit: 500})
	if err != nil {
		return
	}
	var result ThreatPullResult
	if err := json.Unmarshal(resp.Payload, &result); err != nil {
		return
	}
	if len(result.Entries) == 0 {
		return
	}
	applyRaw, _ := json.Marshal(ThreatApplyPayload{Revision: result.Revision, Entries: result.Entries})
	if a.Dispatcher != nil {
		_, _ = a.Dispatcher.Handle(ctx, OpThreatApply, applyRaw)
	}
}

func (a *Agent) handleRequest(ctx context.Context, conn *websocket.Conn, env Envelope) {
	var payload any
	var err error
	if env.Op == OpDesiredApply && a.OnDesired != nil {
		var state DesiredState
		if uerr := json.Unmarshal(env.Payload, &state); uerr != nil {
			err = uerr
		} else {
			err = a.OnDesired(ctx, state)
			payload = map[string]any{"revision": state.Revision}
		}
	} else if a.Dispatcher != nil {
		payload, err = a.Dispatcher.Handle(ctx, env.Op, env.Payload)
	} else {
		err = fmt.Errorf("unsupported op %s", env.Op)
	}
	resp := Envelope{V: ProtocolVersion, ID: env.ID, Op: env.Op}
	if err != nil {
		resp.OK = okFalse()
		resp.Error = err.Error()
	} else {
		resp.OK = okTrue()
		if payload != nil {
			raw, mErr := json.Marshal(payload)
			if mErr != nil {
				resp.OK = okFalse()
				resp.Error = mErr.Error()
			} else {
				resp.Payload = raw
			}
		}
	}
	_ = wsjson.Write(ctx, conn, resp)
}
