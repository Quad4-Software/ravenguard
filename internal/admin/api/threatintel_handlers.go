// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/admin/rbac"
	"github.com/Quad4-Software/ravenguard/internal/agentprotocol"
	"github.com/Quad4-Software/ravenguard/internal/config"
	"github.com/Quad4-Software/ravenguard/internal/threatintel"
)

type threatIntelStatus struct {
	mu         sync.RWMutex
	LastOK     time.Time `json:"last_ok"`
	LastError  string    `json:"last_error,omitempty"`
	LastSource string    `json:"last_source,omitempty"`
	LastStored int       `json:"last_stored,omitempty"`
	LastRev    int64     `json:"last_revision,omitempty"`
}

var tiStatus threatIntelStatus

func (s *Server) threatIntelCfg() config.ThreatIntelConfig {
	if s.Runtime != nil {
		return s.Runtime.Config().ThreatIntel
	}
	return config.ThreatIntelConfig{}
}

func (s *Server) exportOpts() threatintel.ExportOptions {
	cfg := s.threatIntelCfg()
	ttl := cfg.DefaultTTL.Duration
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return threatintel.ExportOptions{ExportRawIP: cfg.ExportRawIP, DefaultTTL: ttl}
}

func (s *Server) defaultTTL() time.Duration {
	cfg := s.threatIntelCfg()
	if cfg.DefaultTTL.Duration > 0 {
		return cfg.DefaultTTL.Duration
	}
	return 24 * time.Hour
}

func (s *Server) allowThreatIntelExport(r *http.Request) bool {
	cfg := s.threatIntelCfg()
	tok := strings.TrimSpace(cfg.ExportToken)
	if tok == "" {
		return false
	}
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && strings.EqualFold(auth[:7], "bearer ") {
		return strings.TrimSpace(auth[7:]) == tok
	}
	return r.Header.Get("X-RG-Export-Token") == tok
}

func (s *Server) handleThreatIntelExportSTIX(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	entries, _, err := s.Store.ListThreatSince(0, 2000)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store")
		return
	}
	raw, n, err := threatintel.ExportSTIX(entries, s.exportOpts())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if actor := actorFrom(r); actor.User.ID != 0 {
		s.audit(actor, r, "threatintel.export", "stix", "")
	}
	w.Header().Set("Content-Type", "application/stix+json; charset=utf-8")
	w.Header().Set("X-RG-Export-Count", itoa(n))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (s *Server) handleThreatIntelExportCSV(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	entries, _, err := s.Store.ListThreatSince(0, 2000)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store")
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="ravenguard-threatintel.csv"`)
	n, err := threatintel.ExportCSV(w, entries, s.exportOpts())
	if err != nil {
		return
	}
	_ = n
	if actor := actorFrom(r); actor.User.ID != 0 {
		s.audit(actor, r, "threatintel.export", "csv", "")
	}
}

func (s *Server) handleThreatIntelIngest(w http.ResponseWriter, r *http.Request) {
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
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "read body")
		return
	}
	format := threatintel.DetectFormat(r.Header.Get("Content-Type"), body)
	if q := r.URL.Query().Get("format"); q != "" {
		format = q
	}
	iocs, err := threatintel.ParseIngestBody(format, body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := s.ingestIOCs(r.Context(), "upload", iocs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(actor, r, "threatintel.ingest", format, "")
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleThreatIntelIngestURL(w http.ResponseWriter, r *http.Request) {
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
		URL    string `json:"url"`
		Format string `json:"format"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.URL) == "" {
		writeErr(w, http.StatusBadRequest, "url required")
		return
	}
	if err := threatintel.ValidateURL(body.URL); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	raw, ct, err := threatintel.FetchURL(r.Context(), body.URL, nil)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	format := body.Format
	if format == "" {
		format = threatintel.DetectFormat(ct, raw)
	}
	iocs, err := threatintel.ParseIngestBody(format, raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := s.ingestIOCs(r.Context(), "url", iocs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(actor, r, "threatintel.ingest", "url", "")
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleThreatIntelAbuseSync(w http.ResponseWriter, r *http.Request) {
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
	cfg := s.threatIntelCfg()
	client := &threatintel.AbuseIPDBClient{APIKey: cfg.AbuseIPDBKey}
	iocs, err := client.FetchBlacklist(r.Context(), cfg.AbuseIPDBMinConfidence, cfg.AbuseIPDBLimit)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	res, err := s.ingestIOCs(r.Context(), "abuseipdb", iocs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(actor, r, "abuseipdb.sync", "", "")
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleThreatIntelAbuseReport(w http.ResponseWriter, r *http.Request) {
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
	cfg := s.threatIntelCfg()
	var body struct {
		IP         string `json:"ip"`
		Comment    string `json:"comment"`
		ConfirmRaw bool   `json:"confirm_raw"`
		Categories []int  `json:"categories"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.IP) == "" {
		writeErr(w, http.StatusBadRequest, "ip required")
		return
	}
	if !cfg.ExportRawIP && !body.ConfirmRaw {
		writeErr(w, http.StatusForbidden, "confirm_raw or export_raw_ip required")
		return
	}
	client := &threatintel.AbuseIPDBClient{APIKey: cfg.AbuseIPDBKey}
	if err := client.ReportIP(r.Context(), body.IP, body.Comment, body.Categories); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.audit(actor, r, "abuseipdb.report", "[ip]", "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleThreatIntelMISPSync(w http.ResponseWriter, r *http.Request) {
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
	cfg := s.threatIntelCfg()
	client := &threatintel.MISPClient{URL: cfg.MISPURL, APIKey: cfg.MISPKey}
	since := time.Now().Add(-24 * time.Hour)
	iocs, err := client.FetchAttributes(r.Context(), since, 500)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	res, err := s.ingestIOCs(r.Context(), "misp", iocs)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.audit(actor, r, "threatintel.ingest", "misp", "")
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleThreatIntelConfig(w http.ResponseWriter, r *http.Request) {
	actor := actorFrom(r)
	switch r.Method {
	case http.MethodGet:
		cfg := s.threatIntelCfg()
		writeJSON(w, http.StatusOK, map[string]any{
			"enabled":                  cfg.Enabled,
			"export_raw_ip":            cfg.ExportRawIP,
			"export_token_set":         cfg.ExportToken != "",
			"abuseipdb_key_set":        cfg.AbuseIPDBKey != "",
			"abuseipdb_min_confidence": cfg.AbuseIPDBMinConfidence,
			"abuseipdb_limit":          cfg.AbuseIPDBLimit,
			"misp_url":                 cfg.MISPURL,
			"misp_key_set":             cfg.MISPKey != "",
			"ingest_urls":              cfg.IngestURLs,
			"ingest_interval":          cfg.IngestInterval.String(),
			"default_ttl":              cfg.DefaultTTL.String(),
			"status":                   tiStatus.snapshot(),
		})
	case http.MethodPut:
		if !rbac.CanWriteConfig(actor.User.Role) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		if !s.checkCSRF(w, r, actor) {
			return
		}
		if s.Runtime == nil {
			writeErr(w, http.StatusBadRequest, "runtime unavailable")
			return
		}
		var body struct {
			Enabled                *bool    `json:"enabled"`
			ExportRawIP            *bool    `json:"export_raw_ip"`
			ExportToken            *string  `json:"export_token"`
			AbuseIPDBKey           *string  `json:"abuseipdb_key"`
			AbuseIPDBMinConfidence *int     `json:"abuseipdb_min_confidence"`
			AbuseIPDBLimit         *int     `json:"abuseipdb_limit"`
			MISPURL                *string  `json:"misp_url"`
			MISPKey                *string  `json:"misp_key"`
			IngestURLs             []string `json:"ingest_urls"`
			IngestInterval         *string  `json:"ingest_interval"`
			DefaultTTL             *string  `json:"default_ttl"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json")
			return
		}
		cfg := s.Runtime.Config()
		ti := cfg.ThreatIntel
		if body.Enabled != nil {
			ti.Enabled = *body.Enabled
		}
		if body.ExportRawIP != nil {
			ti.ExportRawIP = *body.ExportRawIP
		}
		if body.ExportToken != nil {
			ti.ExportToken = *body.ExportToken
		}
		if body.AbuseIPDBKey != nil {
			ti.AbuseIPDBKey = *body.AbuseIPDBKey
		}
		if body.AbuseIPDBMinConfidence != nil {
			ti.AbuseIPDBMinConfidence = *body.AbuseIPDBMinConfidence
		}
		if body.AbuseIPDBLimit != nil {
			ti.AbuseIPDBLimit = *body.AbuseIPDBLimit
		}
		if body.MISPURL != nil {
			ti.MISPURL = *body.MISPURL
		}
		if body.MISPKey != nil {
			ti.MISPKey = *body.MISPKey
		}
		if body.IngestURLs != nil {
			ti.IngestURLs = body.IngestURLs
		}
		if body.IngestInterval != nil {
			if d, err := time.ParseDuration(*body.IngestInterval); err == nil {
				ti.IngestInterval = config.Duration{Duration: d}
			}
		}
		if body.DefaultTTL != nil {
			if d, err := time.ParseDuration(*body.DefaultTTL); err == nil {
				ti.DefaultTTL = config.Duration{Duration: d}
			}
		}
		cfg.ThreatIntel = ti
		s.Runtime.ReplaceConfig(cfg)
		s.audit(actor, r, "threatintel.config", "", "")
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "method")
	}
}

func (s *Server) ingestIOCs(ctx context.Context, source string, iocs []threatintel.IOC) (threatintel.IngestResult, error) {
	res, err := threatintel.IngestIOCs(s.Store, source, iocs, s.defaultTTL())
	if err != nil {
		tiStatus.setErr(source, err.Error())
		return res, err
	}
	if res.Stored > 0 {
		entries, _, _ := s.Store.ListThreatSince(res.Revision-int64(res.Stored), res.Stored+10)
		// Fan-out only the newly stored batch via ingestThreat path using stored keys.
		stored := make([]agentprotocol.ThreatEntry, 0, res.Stored)
		for _, e := range entries {
			if e.Revision > res.Revision-int64(res.Stored) {
				stored = append(stored, e)
			}
		}
		if len(stored) == 0 {
			// Fallback: re-pull by converting again is lossy; fan-out via full pull revision.
			s.fanOutThreat(ctx, source, res.Revision, entries)
		} else {
			s.fanOutThreat(ctx, source, res.Revision, stored)
		}
	}
	tiStatus.setOK(source, res.Stored, res.Revision)
	return res, nil
}

// RunThreatIntelPoller periodically ingests configured URLs on the hub.
func (s *Server) RunThreatIntelPoller(ctx context.Context) {
	for {
		cfg := s.threatIntelCfg()
		interval := cfg.IngestInterval.Duration
		if interval <= 0 {
			interval = time.Hour
		}
		if !cfg.Enabled || len(cfg.IngestURLs) == 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(interval):
				continue
			}
		}
		for _, u := range cfg.IngestURLs {
			u = strings.TrimSpace(u)
			if u == "" {
				continue
			}
			raw, ct, err := threatintel.FetchURL(ctx, u, nil)
			if err != nil {
				tiStatus.setErr("url", err.Error())
				continue
			}
			iocs, err := threatintel.ParseIngestBody(threatintel.DetectFormat(ct, raw), raw)
			if err != nil {
				tiStatus.setErr("url", err.Error())
				continue
			}
			_, _ = s.ingestIOCs(ctx, "poll", iocs)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func (st *threatIntelStatus) setOK(source string, stored int, rev int64) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.LastOK = time.Now().UTC()
	st.LastError = ""
	st.LastSource = source
	st.LastStored = stored
	st.LastRev = rev
}

func (st *threatIntelStatus) setErr(source, msg string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.LastError = msg
	st.LastSource = source
}

func (st *threatIntelStatus) snapshot() map[string]any {
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := map[string]any{
		"last_source":   st.LastSource,
		"last_stored":   st.LastStored,
		"last_revision": st.LastRev,
		"last_error":    st.LastError,
	}
	if !st.LastOK.IsZero() {
		out["last_ok"] = st.LastOK.Format(time.RFC3339)
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
