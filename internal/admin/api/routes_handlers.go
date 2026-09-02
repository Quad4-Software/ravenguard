// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/Quad4-Software/ravenguard/internal/admin/ops"
	"github.com/Quad4-Software/ravenguard/internal/admin/rbac"
	"github.com/Quad4-Software/ravenguard/internal/admin/store"
)

func (s *Server) handleUpstreams(w http.ResponseWriter, r *http.Request) {
	actor := actorFrom(r)
	switch r.Method {
	case http.MethodGet:
		if !rbac.CanRead(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		list, err := s.Store.ListUpstreams()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "list")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"upstreams": list})
	case http.MethodPost:
		if !rbac.CanWriteConfig(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if !s.checkCSRF(w, r, actor) {
			return
		}
		var body store.UpstreamRow
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		up, err := s.Store.CreateUpstream(body)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		_ = s.reloadRouting()
		s.audit(actor, r, "upstreams.create", up.ID, up.Name)
		writeJSON(w, http.StatusCreated, up)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method")
	}
}

func (s *Server) handleUpstreamID(w http.ResponseWriter, r *http.Request) {
	actor := actorFrom(r)
	id := pathID(r, "upstreams")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !rbac.CanRead(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		up, err := s.Store.GetUpstream(id)
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "get")
			return
		}
		writeJSON(w, http.StatusOK, up)
	case http.MethodPut, http.MethodPatch:
		if !rbac.CanWriteConfig(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if !s.checkCSRF(w, r, actor) {
			return
		}
		var body store.UpstreamRow
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		up, err := s.Store.UpdateUpstream(id, body)
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		_ = s.reloadRouting()
		s.audit(actor, r, "upstreams.update", up.ID, up.Name)
		writeJSON(w, http.StatusOK, up)
	case http.MethodDelete:
		if !rbac.CanWriteConfig(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if !s.checkCSRF(w, r, actor) {
			return
		}
		err := s.Store.DeleteUpstream(id)
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		if errors.Is(err, store.ErrInUse) {
			writeErr(w, http.StatusConflict, "in use")
			return
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		_ = s.reloadRouting()
		s.audit(actor, r, "upstreams.delete", id, "")
		writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method")
	}
}

func (s *Server) handleRoutes(w http.ResponseWriter, r *http.Request) {
	actor := actorFrom(r)
	switch r.Method {
	case http.MethodGet:
		if !rbac.CanRead(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		list, err := s.Store.ListRoutes()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "list")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"routes": list})
	case http.MethodPost:
		if !rbac.CanWriteConfig(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if !s.checkCSRF(w, r, actor) {
			return
		}
		var body store.RouteRow
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		rt, err := s.Store.CreateRoute(body)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		_ = s.reloadRouting()
		s.audit(actor, r, "routes.create", rt.ID, rt.Name)
		writeJSON(w, http.StatusCreated, rt)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method")
	}
}

func (s *Server) handleRouteID(w http.ResponseWriter, r *http.Request) {
	actor := actorFrom(r)
	id := pathID(r, "routes")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !rbac.CanRead(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		rt, err := s.Store.GetRoute(id)
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "get")
			return
		}
		writeJSON(w, http.StatusOK, rt)
	case http.MethodPut, http.MethodPatch:
		if !rbac.CanWriteConfig(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if !s.checkCSRF(w, r, actor) {
			return
		}
		var body store.RouteRow
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		rt, err := s.Store.UpdateRoute(id, body)
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		_ = s.reloadRouting()
		s.audit(actor, r, "routes.update", rt.ID, rt.Name)
		writeJSON(w, http.StatusOK, rt)
	case http.MethodDelete:
		if !rbac.CanWriteConfig(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if !s.checkCSRF(w, r, actor) {
			return
		}
		err := s.Store.DeleteRoute(id)
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		_ = s.reloadRouting()
		s.audit(actor, r, "routes.delete", id, "")
		writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method")
	}
}

func (s *Server) handleAccessPolicies(w http.ResponseWriter, r *http.Request) {
	actor := actorFrom(r)
	switch r.Method {
	case http.MethodGet:
		if !rbac.CanRead(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		list, err := s.Store.ListAccessPolicies()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "list")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"access_policies": list})
	case http.MethodPost:
		if !rbac.CanWriteConfig(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if !s.checkCSRF(w, r, actor) {
			return
		}
		var body store.AccessPolicyRow
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		p, err := s.Store.CreateAccessPolicy(body)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		_ = s.reloadRouting()
		s.audit(actor, r, "access_policies.create", p.ID, p.Name)
		writeJSON(w, http.StatusCreated, p)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method")
	}
}

func (s *Server) handleAccessPolicyID(w http.ResponseWriter, r *http.Request) {
	actor := actorFrom(r)
	id := pathID(r, "access-policies")
	if id == "" {
		writeErr(w, http.StatusBadRequest, "invalid id")
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !rbac.CanRead(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		p, err := s.Store.GetAccessPolicy(id)
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "get")
			return
		}
		writeJSON(w, http.StatusOK, p)
	case http.MethodPut, http.MethodPatch:
		if !rbac.CanWriteConfig(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if !s.checkCSRF(w, r, actor) {
			return
		}
		var body store.AccessPolicyRow
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		p, err := s.Store.UpdateAccessPolicy(id, body)
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		_ = s.reloadRouting()
		s.audit(actor, r, "access_policies.update", p.ID, p.Name)
		writeJSON(w, http.StatusOK, p)
	case http.MethodDelete:
		if !rbac.CanWriteConfig(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if !s.checkCSRF(w, r, actor) {
			return
		}
		err := s.Store.DeleteAccessPolicy(id)
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		_ = s.reloadRouting()
		s.audit(actor, r, "access_policies.delete", id, "")
		writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method")
	}
}

func (s *Server) handleCerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	actor := actorFrom(r)
	if !rbac.CanRead(actor.User.Role) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	status := s.certStatus()
	writeJSON(w, http.StatusOK, map[string]any{"certs": status})
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	actor := actorFrom(r)
	if !rbac.CanRead(actor.User.Role) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	level := r.URL.Query().Get("level")
	entries := s.logSnapshot(limit, level)
	writeJSON(w, http.StatusOK, map[string]any{"logs": entries})
}

func (s *Server) handleCertsPath(w http.ResponseWriter, r *http.Request) {
	actor := actorFrom(r)
	rest := pathAfter(r, "certs")
	if rest == "" {
		s.handleCerts(w, r)
		return
	}
	parts := strings.Split(rest, "/")

	if len(parts) == 1 && parts[0] == "manage" {
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "method")
			return
		}
		if !rbac.CanWriteConfig(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if !s.checkCSRF(w, r, actor) {
			return
		}
		var body struct {
			Hosts []string `json:"hosts"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		if err := s.acmeManage(r, body.Hosts); err != nil {
			if errors.Is(err, ops.ErrACMEManageUnavailable) {
				writeErr(w, http.StatusBadRequest, "unavailable")
				return
			}
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.audit(actor, r, "certs.manage", strings.Join(body.Hosts, ","), "")
		writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
		return
	}

	if len(parts) == 2 && parts[1] == "renew" {
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "method")
			return
		}
		if !rbac.CanWriteConfig(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if !s.checkCSRF(w, r, actor) {
			return
		}
		host := strings.TrimSpace(parts[0])
		if host == "" {
			writeErr(w, http.StatusBadRequest, "invalid host")
			return
		}
		if err := s.certRenew(r, host); err != nil {
			if errors.Is(err, ops.ErrCertRenewUnavailable) {
				writeErr(w, http.StatusBadRequest, "unavailable")
				return
			}
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.audit(actor, r, "certs.renew", host, "")
		writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
		return
	}

	if len(parts) != 1 {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	host := strings.TrimSpace(parts[0])
	if host == "" || host == "manage" {
		writeErr(w, http.StatusBadRequest, "invalid host")
		return
	}

	switch r.Method {
	case http.MethodGet:
		if !rbac.CanRead(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		detail, err := s.certDetail(host)
		if err != nil {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeJSON(w, http.StatusOK, detail)
	case http.MethodPut:
		if !rbac.CanWriteConfig(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if !s.checkCSRF(w, r, actor) {
			return
		}
		var body struct {
			CertPEM string `json:"cert_pem"`
			KeyPEM  string `json:"key_pem"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		if err := s.manualCertPut(host, body.CertPEM, body.KeyPEM); err != nil {
			if errors.Is(err, ops.ErrManualCertUnavailable) {
				writeErr(w, http.StatusBadRequest, "unavailable")
				return
			}
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.audit(actor, r, "certs.put", host, "manual")
		writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
	case http.MethodDelete:
		if !rbac.CanWriteConfig(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if !s.checkCSRF(w, r, actor) {
			return
		}
		if err := s.manualCertDelete(host); err != nil {
			if errors.Is(err, ops.ErrManualCertUnavailable) {
				writeErr(w, http.StatusBadRequest, "unavailable")
				return
			}
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.audit(actor, r, "certs.delete", host, "manual")
		writeJSON(w, http.StatusOK, map[string]string{"ok": "1"})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method")
	}
}

func (s *Server) reloadRouting() error {
	if s.ReloadRoutes != nil {
		return s.ReloadRoutes()
	}
	if s.Runtime != nil {
		return s.Runtime.ReloadRouting()
	}
	return nil
}

func (s *Server) certStatus() any {
	if s.CertStatus != nil {
		return s.CertStatus()
	}
	if s.Runtime != nil {
		return s.Runtime.CertStatusView()
	}
	return []any{}
}

func (s *Server) certRenew(r *http.Request, host string) error {
	ctx := r.Context()
	if s.Runtime != nil && s.Runtime.RootCtx != nil {
		ctx = s.Runtime.RootCtx
	}
	if s.CertRenew != nil {
		return s.CertRenew(ctx, host)
	}
	if s.Runtime != nil {
		return s.Runtime.RenewCert(ctx, host)
	}
	return ops.ErrCertRenewUnavailable
}

func (s *Server) logSnapshot(limit int, level string) any {
	if s.LogSnapshot != nil {
		return s.LogSnapshot(limit, level)
	}
	if s.Runtime != nil {
		return s.Runtime.LogsView(limit, level)
	}
	return []any{}
}

func (s *Server) certDetail(host string) (any, error) {
	if s.CertDetail != nil {
		return s.CertDetail(host)
	}
	if s.Runtime != nil {
		return s.Runtime.CertDetailView(host)
	}
	return nil, errors.New("cert detail unavailable")
}

func (s *Server) manualCertPut(host, certPEM, keyPEM string) error {
	if s.ManualCertPut != nil {
		return s.ManualCertPut(host, certPEM, keyPEM)
	}
	if s.Runtime != nil {
		return s.Runtime.PutManualCert(host, certPEM, keyPEM)
	}
	return ops.ErrManualCertUnavailable
}

func (s *Server) manualCertDelete(host string) error {
	if s.ManualCertDelete != nil {
		return s.ManualCertDelete(host)
	}
	if s.Runtime != nil {
		return s.Runtime.DeleteManualCert(host)
	}
	return ops.ErrManualCertUnavailable
}

func (s *Server) acmeManage(r *http.Request, hosts []string) error {
	ctx := r.Context()
	if s.Runtime != nil && s.Runtime.RootCtx != nil {
		ctx = s.Runtime.RootCtx
	}
	if s.ACMEManage != nil {
		return s.ACMEManage(ctx, hosts)
	}
	if s.Runtime != nil {
		return s.Runtime.ManageACMEHosts(ctx, hosts)
	}
	return ops.ErrACMEManageUnavailable
}

func pathID(r *http.Request, resource string) string {
	rest := pathAfter(r, resource)
	if rest == "" || strings.Contains(rest, "/") {
		return ""
	}
	return rest
}

func pathAfter(r *http.Request, resource string) string {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	for i := 0; i < len(parts); i++ {
		if parts[i] == resource && i+1 < len(parts) {
			return strings.Join(parts[i+1:], "/")
		}
	}
	return ""
}
