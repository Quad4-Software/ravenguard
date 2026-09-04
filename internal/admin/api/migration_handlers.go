// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/Quad4-Software/ravenguard/internal/admin/rbac"
	"github.com/Quad4-Software/ravenguard/internal/admin/store"
	"github.com/Quad4-Software/ravenguard/internal/agentprotocol"
)

func (s *Server) handleMigrations(w http.ResponseWriter, r *http.Request) {
	actor := actorFrom(r)
	switch r.Method {
	case http.MethodGet:
		list, err := s.Store.ListServiceMigrations()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"migrations": list})
	case http.MethodPost:
		if !rbac.CanWriteConfig(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		var body struct {
			FromProxyID string   `json:"from_proxy_id"`
			ToProxyID   string   `json:"to_proxy_id"`
			RouteIDs    []string `json:"route_ids"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		fromP, err := s.Store.GetProxy(body.FromProxyID)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "from proxy not found")
			return
		}
		toP, err := s.Store.GetProxy(body.ToProxyID)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "to proxy not found")
			return
		}
		checklist := buildDNSChecklist(body.RouteIDs, fromP, toP, s.Store)
		uid := int(actor.User.ID)
		m, err := s.Store.CreateServiceMigration(body.FromProxyID, body.ToProxyID, body.RouteIDs, &uid, checklist)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.audit(actor, r, "migration.create", m.ID, body.FromProxyID+"->"+body.ToProxyID)
		writeJSON(w, http.StatusCreated, map[string]any{"migration": m})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleMigrationID(w http.ResponseWriter, r *http.Request) {
	actor := actorFrom(r)
	path := strings.TrimPrefix(r.URL.Path, strings.TrimSuffix(s.Admin.BasePath, "/")+"/api/v1/migrations/")
	path = strings.Trim(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	id := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	m, err := s.Store.GetServiceMigration(id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	if action == "" && r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]any{"migration": m})
		return
	}
	if !rbac.CanWriteConfig(actor.User.Role) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}

	switch {
	case action == "prep" && r.Method == http.MethodPost:
		if err := s.migrationPrep(r, &m); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.audit(actor, r, "migration.prep", m.ID, "")
		writeJSON(w, http.StatusOK, map[string]any{"migration": m})
	case action == "complete" && r.Method == http.MethodPost:
		if err := s.migrationComplete(r, &m); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.audit(actor, r, "migration.complete", m.ID, "")
		writeJSON(w, http.StatusOK, map[string]any{"migration": m})
	case action == "abort" && r.Method == http.MethodPost:
		if err := s.migrationAbort(r, &m); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		s.audit(actor, r, "migration.abort", m.ID, "")
		writeJSON(w, http.StatusOK, map[string]any{"migration": m})
	default:
		writeErr(w, http.StatusNotFound, "not found")
	}
}

func buildDNSChecklist(routeIDs []string, fromP, toP store.ProxyRow, st *store.Store) []store.DNSChecklistItem {
	hosts := map[string]struct{}{}
	for _, id := range routeIDs {
		rt, err := st.GetRoute(id)
		if err != nil {
			continue
		}
		for _, h := range rt.Hosts {
			if h != "" && h != "*" {
				hosts[h] = struct{}{}
			}
		}
	}
	var out []store.DNSChecklistItem
	for h := range hosts {
		item := store.DNSChecklistItem{
			Host:     h,
			FromIPv4: fromP.PublicIPv4,
			FromIPv6: fromP.PublicIPv6,
			ToIPv4:   toP.PublicIPv4,
			ToIPv6:   toP.PublicIPv6,
			Note:     "Update DNS so this hostname points at the destination proxy public IP. Lower TTL ahead of cutover if possible.",
		}
		if toP.PublicIPv4 != "" {
			item.SuggestedA = toP.PublicIPv4
		}
		if toP.PublicIPv6 != "" {
			item.SuggestedAAAA = toP.PublicIPv6
		}
		out = append(out, item)
	}
	return out
}

func (s *Server) migrationPrep(r *http.Request, m *store.ServiceMigration) error {
	if m.Phase != "created" && m.Phase != "aborted" {
		return errors.New("migration not in created phase")
	}
	for _, rid := range m.RouteIDs {
		if err := s.Store.SetRouteProxy(rid, m.ToProxyID); err != nil {
			return err
		}
	}
	// Also keep routes on source until complete: temporarily assign to dest for desired state,
	// then rebuild both. For dual-ready we push dest with routes, source still has them until complete.
	// Re-assign was permanent above - restore source ownership until complete by writing both snapshots.
	// Simpler approach: set proxy_id to dest now (dest serves after DNS), source desired state rebuilt without them at complete.
	_ = s.copyCerts(r, m)
	if err := s.pushDesired(r.Context(), m.ToProxyID); err != nil {
		return err
	}
	// Rebuild source without moved routes: temporarily they already point to dest, so source push drops them.
	_ = s.pushDesired(r.Context(), m.FromProxyID)
	// For dual-ready until DNS flips, re-add routes to source desired by pushing a merged snapshot.
	// Restore route proxy_id to source for serving until complete, while dest also has staged copy via migrationStaging.
	for _, rid := range m.RouteIDs {
		_ = s.Store.SetRouteProxy(rid, m.FromProxyID)
	}
	if err := s.stageRoutesOnDest(r.Context(), m); err != nil {
		return err
	}
	updated, err := s.Store.UpdateServiceMigration(m.ID, "prepared", "destination staged; update DNS then complete", m.DNSChecklist)
	if err != nil {
		return err
	}
	*m = updated
	return nil
}

func (s *Server) stageRoutesOnDest(ctx context.Context, m *store.ServiceMigration) error {
	// Build dest desired including migration routes even while DB still assigns them to source.
	state, err := s.BuildDesiredState(m.ToProxyID)
	if err != nil {
		return err
	}
	routes, _ := s.Store.ListRoutes()
	upstreams, _ := s.Store.ListUpstreams()
	policies, _ := s.Store.ListAccessPolicies()
	allSchemas, _ := s.Store.ListAPISchemas()
	var extra []store.RouteRow
	for _, rid := range m.RouteIDs {
		for _, rt := range routes {
			if rt.ID == rid {
				rt.ProxyID = m.ToProxyID
				extra = append(extra, rt)
			}
		}
	}
	if len(extra) == 0 {
		return s.pushDesired(ctx, m.ToProxyID)
	}
	var snap agentprotocol.RoutingSnapshot
	_ = json.Unmarshal(state.Routing, &snap)
	var existing []store.RouteRow
	_ = json.Unmarshal(snap.Routes, &existing)
	existing = append(existing, extra...)
	snap.Routes, _ = json.Marshal(existing)

	var existingUp []store.UpstreamRow
	_ = json.Unmarshal(snap.Upstreams, &existingUp)
	upByID := map[string]store.UpstreamRow{}
	for _, u := range existingUp {
		upByID[u.ID] = u
	}
	var existingPol []store.AccessPolicyRow
	_ = json.Unmarshal(snap.AccessPolicies, &existingPol)
	polByID := map[string]store.AccessPolicyRow{}
	for _, p := range existingPol {
		polByID[p.ID] = p
	}
	var existingSchema []store.APISchemaRow
	_ = json.Unmarshal(snap.APISchemas, &existingSchema)
	schemaByID := map[string]store.APISchemaRow{}
	for _, sc := range existingSchema {
		schemaByID[sc.ID] = sc
	}
	for _, rt := range extra {
		if up, err := findUpstream(upstreams, rt.UpstreamID); err == nil {
			upByID[up.ID] = up
		}
		if rt.AccessPolicyID != nil {
			if p, err := findPolicy(policies, *rt.AccessPolicyID); err == nil {
				polByID[p.ID] = p
			}
		}
		if rt.OpenAPISchemaID != nil {
			if sc, err := findSchema(allSchemas, *rt.OpenAPISchemaID); err == nil {
				schemaByID[sc.ID] = sc
			}
		}
	}
	upList := make([]store.UpstreamRow, 0, len(upByID))
	for _, u := range upByID {
		upList = append(upList, u)
	}
	polList := make([]store.AccessPolicyRow, 0, len(polByID))
	for _, p := range polByID {
		polList = append(polList, p)
	}
	schemaList := make([]store.APISchemaRow, 0, len(schemaByID))
	for _, sc := range schemaByID {
		schemaList = append(schemaList, sc)
	}
	snap.Upstreams, _ = json.Marshal(upList)
	snap.AccessPolicies, _ = json.Marshal(polList)
	snap.APISchemas, _ = json.Marshal(schemaList)

	state.Routing, _ = json.Marshal(snap)
	rev, _ := s.Store.NextDesiredRevision(m.ToProxyID)
	state.Revision = rev
	if err := s.Store.SetDesiredState(m.ToProxyID, state); err != nil {
		return err
	}
	return s.targetFor(m.ToProxyID).ApplyDesired(ctx, state)
}

func (s *Server) copyCerts(r *http.Request, m *store.ServiceMigration) error {
	from := s.targetFor(m.FromProxyID)
	to := s.targetFor(m.ToProxyID)
	for _, item := range m.DNSChecklist {
		env, err := from.Call(r.Context(), agentprotocol.OpCertsExport, agentprotocol.CertHostPayload{Host: item.Host})
		if err != nil {
			continue
		}
		var exported agentprotocol.CertExportPayload
		if uerr := json.Unmarshal(env.Payload, &exported); uerr != nil || exported.CertPEM == "" || exported.KeyPEM == "" {
			continue
		}
		_, _ = to.Call(r.Context(), agentprotocol.OpCertsPut, agentprotocol.CertHostPayload{
			Host: item.Host, CertPEM: exported.CertPEM, KeyPEM: exported.KeyPEM,
		})
	}
	hosts := make([]string, 0, len(m.DNSChecklist))
	for _, item := range m.DNSChecklist {
		hosts = append(hosts, item.Host)
	}
	if len(hosts) > 0 {
		_, _ = to.Call(r.Context(), agentprotocol.OpCertsManage, agentprotocol.CertManagePayload{Hosts: hosts})
	}
	return nil
}

func (s *Server) migrationComplete(r *http.Request, m *store.ServiceMigration) error {
	if m.Phase != "prepared" {
		return errors.New("migration must be prepared first")
	}
	for _, rid := range m.RouteIDs {
		if err := s.Store.SetRouteProxy(rid, m.ToProxyID); err != nil {
			return err
		}
	}
	if err := s.pushDesired(r.Context(), m.ToProxyID); err != nil {
		return err
	}
	if err := s.pushDesired(r.Context(), m.FromProxyID); err != nil {
		return err
	}
	updated, err := s.Store.UpdateServiceMigration(m.ID, "completed", "cut over", nil)
	if err != nil {
		return err
	}
	*m = updated
	return nil
}

func (s *Server) migrationAbort(r *http.Request, m *store.ServiceMigration) error {
	if m.Phase == "completed" {
		return errors.New("cannot abort completed migration")
	}
	for _, rid := range m.RouteIDs {
		_ = s.Store.SetRouteProxy(rid, m.FromProxyID)
	}
	_ = s.pushDesired(r.Context(), m.FromProxyID)
	_ = s.pushDesired(r.Context(), m.ToProxyID)
	updated, err := s.Store.UpdateServiceMigration(m.ID, "aborted", "aborted by operator", nil)
	if err != nil {
		return err
	}
	*m = updated
	return nil
}
