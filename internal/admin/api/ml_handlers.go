// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/Quad4-Software/ravenguard/internal/admin/rbac"
	"github.com/Quad4-Software/ravenguard/internal/ml/adapt"
)

func (s *Server) handleMLSamples(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	actor := actorFrom(r)
	if !rbac.CanRead(actor.User.Role) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	unlabeled := r.URL.Query().Get("unlabeled") == "1"
	list, err := s.Store.ListMLSamples(limit, unlabeled)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"samples": list})
}

func (s *Server) handleMLSampleID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPatch {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	actor := actorFrom(r)
	if !rbac.CanWriteConfig(actor.User.Role) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	idStr := r.URL.Path
	if i := strings.LastIndex(idStr, "/"); i >= 0 {
		idStr = idStr[i+1:]
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	var body struct {
		Label string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	label := strings.ToLower(strings.TrimSpace(body.Label))
	switch label {
	case "fp", "tp", "ignore":
	default:
		writeErr(w, http.StatusBadRequest, "label must be fp, tp, or ignore")
		return
	}
	if err := s.Store.LabelMLSample(id, label); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": id, "label": label})
}

func (s *Server) handleMLAdapt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "method")
		return
	}
	actor := actorFrom(r)
	if !rbac.CanWriteConfig(actor.User.Role) {
		writeErr(w, http.StatusForbidden, "forbidden")
		return
	}
	labeled, err := s.Store.ListLabeledMLSamples(2000)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var samples []adapt.LabeledSample
	for _, row := range labeled {
		lab := 0.0
		if row.Label == "tp" {
			lab = 1
		}
		samples = append(samples, adapt.LabeledSample{Features: row.Features, Label: lab})
	}
	model, err := adapt.TrainOverlay(samples, 3, 40, 0.05)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	path := "assets/ml/adapt.bin"
	if s.Runtime != nil {
		cfg := s.Runtime.Config()
		if cfg.ML.AdaptPath != "" {
			path = cfg.ML.AdaptPath
		}
	}
	if err := model.Save(path); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.Runtime != nil && s.Runtime.ML != nil {
		s.Runtime.ML.SetAdapt(model)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "path": path, "hash": model.Hash, "samples": len(samples)})
}
