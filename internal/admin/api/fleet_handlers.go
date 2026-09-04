// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/Quad4-Software/ravenguard/internal/admin/ops"
	"github.com/Quad4-Software/ravenguard/internal/admin/rbac"
	"github.com/Quad4-Software/ravenguard/internal/admin/store"
	"github.com/Quad4-Software/ravenguard/internal/agentprotocol"
)

func (s *Server) handleProxies(w http.ResponseWriter, r *http.Request) {
	actor := actorFrom(r)
	switch r.Method {
	case http.MethodGet:
		list, err := s.Store.ListProxies()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		online := map[string]bool{}
		if s.AgentRegistry != nil {
			for _, id := range s.AgentRegistry.ListOnline() {
				online[id] = true
			}
		}
		for i := range list {
			list[i].Online = online[list[i].ID]
		}
		hubURL := strings.TrimSpace(s.HubPublicURL)
		pub := ""
		if s.HubKeys != nil {
			pub = s.HubKeys.PublicKeyBase64()
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"proxies":      list,
			"hub_url":      hubURL,
			"hub_pubkey":   pub,
			"connect_path": agentprotocol.ConnectPath,
		})
	case http.MethodPost:
		if !rbac.CanWriteConfig(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		var body struct {
			Name       string   `json:"name"`
			Tags       []string `json:"tags"`
			PublicIPv4 string   `json:"public_ipv4"`
			PublicIPv6 string   `json:"public_ipv6"`
			Universal  bool     `json:"universal"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		if body.Universal && !rbac.CanManageOwners(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "universal tokens require owner")
			return
		}
		row, token, err := s.Store.CreateProxy(body.Name, body.Tags, body.PublicIPv4, body.PublicIPv6, body.Universal)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.audit(actor, r, "proxy.create", row.ID, row.Name)
		writeJSON(w, http.StatusCreated, map[string]any{
			"proxy":            row,
			"enrollment_token": token,
			"hub_url":          strings.TrimSpace(s.HubPublicURL),
			"hub_pubkey":       s.hubPub(),
			"install": map[string]string{
				"hub_url":    strings.TrimSpace(s.HubPublicURL),
				"token":      token,
				"hub_pubkey": s.hubPub(),
			},
		})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleProxyID(w http.ResponseWriter, r *http.Request) {
	actor := actorFrom(r)
	id := strings.TrimPrefix(r.URL.Path, strings.TrimSuffix(s.apiBase(), "/")+"/api/v1/proxies/")
	id = strings.Trim(id, "/")
	if id == "" {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	parts := strings.Split(id, "/")
	proxyID := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch {
	case action == "rotate-token" && r.Method == http.MethodPost:
		if !rbac.CanWriteConfig(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		row, token, err := s.Store.RotateProxyToken(proxyID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeErr(w, http.StatusNotFound, "not found")
				return
			}
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.audit(actor, r, "proxy.rotate_token", proxyID, "")
		writeJSON(w, http.StatusOK, map[string]any{"proxy": row, "enrollment_token": token, "hub_pubkey": s.hubPub(), "hub_url": s.HubPublicURL})
		return
	case action == "push" && r.Method == http.MethodPost:
		if !rbac.CanWriteConfig(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if err := s.pushDesired(r.Context(), proxyID); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.audit(actor, r, "proxy.push", proxyID, "")
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	case action == "status" && r.Method == http.MethodGet:
		target := s.targetFor(proxyID)
		st, err := target.Status(r.Context())
		if err != nil {
			writeErr(w, http.StatusBadGateway, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, st)
		return
	case action != "":
		writeErr(w, http.StatusNotFound, "not found")
		return
	}

	switch r.Method {
	case http.MethodGet:
		row, err := s.Store.GetProxy(proxyID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeErr(w, http.StatusNotFound, "not found")
				return
			}
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if s.AgentRegistry != nil {
			_, row.Online = s.AgentRegistry.Get(proxyID)
		}
		writeJSON(w, http.StatusOK, map[string]any{"proxy": row})
	case http.MethodPut, http.MethodPatch:
		if !rbac.CanWriteConfig(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		var body struct {
			Name       string   `json:"name"`
			Tags       []string `json:"tags"`
			PublicIPv4 string   `json:"public_ipv4"`
			PublicIPv6 string   `json:"public_ipv6"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		row, err := s.Store.UpdateProxy(proxyID, body.Name, body.Tags, body.PublicIPv4, body.PublicIPv6)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeErr(w, http.StatusNotFound, "not found")
				return
			}
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.audit(actor, r, "proxy.update", proxyID, row.Name)
		writeJSON(w, http.StatusOK, map[string]any{"proxy": row})
	case http.MethodDelete:
		if !rbac.CanWriteConfig(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if err := s.Store.DeleteProxy(proxyID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeErr(w, http.StatusNotFound, "not found")
				return
			}
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.audit(actor, r, "proxy.delete", proxyID, "")
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) hubPub() string {
	if s.HubKeys == nil {
		return ""
	}
	return s.HubKeys.PublicKeyBase64()
}

func (s *Server) apiBase() string {
	return strings.TrimSuffix(s.Admin.BasePath, "/")
}

func (s *Server) targetFor(proxyID string) ops.ProxyTarget {
	proxyID = strings.TrimSpace(proxyID)
	if proxyID == "" || proxyID == "local" {
		if s.LocalTarget != nil {
			return s.LocalTarget
		}
		return &ops.LocalTarget{Runtime: s.Runtime}
	}
	// Fleet proxy IDs must never fall back to the hub/local runtime.
	if _, err := s.Store.GetProxy(proxyID); err == nil {
		if s.AgentRegistry != nil {
			if _, ok := s.AgentRegistry.Get(proxyID); ok {
				return &ops.RemoteTarget{Registry: s.AgentRegistry, ProxyID: proxyID}
			}
		}
		return &ops.OfflineTarget{ProxyID: proxyID}
	}
	if s.AgentRegistry != nil {
		if _, ok := s.AgentRegistry.Get(proxyID); ok {
			return &ops.RemoteTarget{Registry: s.AgentRegistry, ProxyID: proxyID}
		}
	}
	return &ops.OfflineTarget{ProxyID: proxyID}
}

func (s *Server) pushDesired(ctx context.Context, proxyID string) error {
	state, err := s.BuildDesiredState(proxyID)
	if err != nil {
		return err
	}
	if err := s.Store.SetDesiredState(proxyID, state); err != nil {
		return err
	}
	target := s.targetFor(proxyID)
	return target.ApplyDesired(ctx, state)
}
