// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/admin/rbac"
	"github.com/Quad4-Software/ravenguard/internal/tunnel"
)

func (s *Server) handleTunnelTicket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	actor := actorFrom(r)
	if !rbac.CanWriteOps(actor.User.Role) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	if !s.checkCSRF(w, r, actor) {
		return
	}
	var body struct {
		ConnectorID string `json:"connector_id"`
		EdgeID      string `json:"edge_id"`
		TTL         string `json:"ttl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.ConnectorID) == "" {
		writeErr(w, http.StatusBadRequest, "connector_id required")
		return
	}
	secret := s.tunnelTicketSecret()
	if len(secret) == 0 {
		writeErr(w, http.StatusBadRequest, "tunnel ticket key not configured")
		return
	}
	ttl := 15 * time.Minute
	if body.TTL != "" {
		if d, err := time.ParseDuration(body.TTL); err == nil && d > 0 {
			ttl = d
		}
	}
	raw, err := tunnel.IssueTicket(secret, body.ConnectorID, body.EdgeID, ttl)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(actor, r, "tunnel.ticket", body.ConnectorID, body.EdgeID)
	writeJSON(w, http.StatusOK, map[string]any{
		"ticket":       raw,
		"connector_id": body.ConnectorID,
		"edge_id":      body.EdgeID,
		"ttl":          ttl.String(),
	})
}

func (s *Server) tunnelTicketSecret() []byte {
	if s.Runtime == nil {
		return nil
	}
	cfg := s.Runtime.Config()
	if k := strings.TrimSpace(cfg.Tunnel.TicketKey); k != "" {
		return []byte(k)
	}
	if k := strings.TrimSpace(cfg.Challenge.Secret); k != "" {
		return []byte(k)
	}
	return nil
}
