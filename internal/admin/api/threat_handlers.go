// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/admin/rbac"
	"github.com/Quad4-Software/ravenguard/internal/agentprotocol"
)

// HandleAgentThreatOp processes agent-initiated threat.report / threat.pull on the hub.
func (s *Server) HandleAgentThreatOp(ctx context.Context, proxyID, op string, payload json.RawMessage) (any, error) {
	switch op {
	case agentprotocol.OpThreatReport:
		var p agentprotocol.ThreatReportPayload
		if err := json.Unmarshal(payload, &p); err != nil {
			return nil, err
		}
		return s.ingestThreat(ctx, proxyID, p.Entries)
	case agentprotocol.OpThreatPull:
		var p agentprotocol.ThreatPullPayload
		_ = json.Unmarshal(payload, &p)
		entries, rev, err := s.Store.ListThreatSince(p.SinceRevision, p.Limit)
		if err != nil {
			return nil, err
		}
		return agentprotocol.ThreatPullResult{Revision: rev, Entries: entries}, nil
	default:
		return nil, errUnsupportedThreatOp
	}
}

var errUnsupportedThreatOp = errString("unsupported threat op")

type errString string

func (e errString) Error() string { return string(e) }

func (s *Server) ingestThreat(ctx context.Context, sourceProxyID string, entries []agentprotocol.ThreatEntry) (any, error) {
	stored, rev, err := s.Store.InsertThreatEntries(sourceProxyID, entries)
	if err != nil {
		return nil, err
	}
	if len(stored) == 0 {
		return map[string]any{"revision": rev, "stored": 0}, nil
	}
	s.fanOutThreat(ctx, sourceProxyID, rev, stored)
	return map[string]any{"revision": rev, "stored": len(stored)}, nil
}

func (s *Server) fanOutThreat(ctx context.Context, sourceProxyID string, rev int64, entries []agentprotocol.ThreatEntry) {
	if s.AgentRegistry == nil || len(entries) == 0 {
		return
	}
	online := s.AgentRegistry.ListOnline()
	targets := make([]string, 0, len(online))
	for _, id := range online {
		if id == sourceProxyID {
			continue
		}
		targets = append(targets, id)
	}
	if len(targets) == 0 {
		return
	}
	payload := agentprotocol.ThreatApplyPayload{Revision: rev, Entries: entries}
	go func() {
		c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = ctx
		_ = s.AgentRegistry.FanOut(c, targets, agentprotocol.OpThreatApply, payload)
	}()
}

func (s *Server) handleThreat(w http.ResponseWriter, r *http.Request) {
	actor := actorFrom(r)
	switch r.Method {
	case http.MethodGet:
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		entries, rev, err := s.Store.ListThreatAdmin(limit)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "store")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"revision": rev, "entries": entries})
	case http.MethodPost:
		if !rbac.CanWriteOps(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if !s.checkCSRF(w, r, actor) {
			return
		}
		var body struct {
			KeyType string `json:"key_type"`
			Key     string `json:"key"`
			Reason  string `json:"reason"`
			TTL     string `json:"ttl"`
			Share   bool   `json:"share"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		body.KeyType = strings.ToLower(strings.TrimSpace(body.KeyType))
		body.Key = strings.TrimSpace(body.Key)
		if body.Key == "" || body.KeyType == "" {
			writeErr(w, http.StatusBadRequest, "key_type and key required")
			return
		}
		ttl := int64(600)
		if body.TTL != "" {
			if d, err := time.ParseDuration(body.TTL); err == nil && d > 0 {
				ttl = int64(d / time.Second)
			}
		}
		now := time.Now()
		entry := agentprotocol.ThreatEntry{
			KeyType:       body.KeyType,
			Key:           body.Key,
			TTLSeconds:    ttl,
			Reason:        strings.TrimSpace(body.Reason),
			CreatedAtUnix: now.Unix(),
			ExpiresAtUnix: now.Add(time.Duration(ttl) * time.Second).Unix(),
		}
		if body.KeyType == agentprotocol.ThreatKeyBind || body.KeyType == agentprotocol.ThreatKeyIPHash {
			if s.Runtime != nil && s.Runtime.Protect != nil {
				s.Runtime.Protect.BanUntil(body.Key, now.Add(time.Duration(ttl)*time.Second))
			}
		}
		res, err := s.ingestThreat(r.Context(), "admin", []agentprotocol.ThreatEntry{entry})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.audit(actor, r, "threat.create", body.KeyType, body.Reason)
		writeJSON(w, http.StatusOK, res)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method")
	}
}
