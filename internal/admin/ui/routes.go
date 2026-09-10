// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ui

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

func (u *UI) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		u.render(w, r, "login", PageData{PageTitle: "Sign in"})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		u.render(w, r, "login", PageData{PageTitle: "Sign in", Error: "invalid form"})
		return
	}

	body := map[string]any{
		"username": r.FormValue("username"),
		"password": r.FormValue("password"),
	}

	status, resp, hdr, err := u.apiCall(r, http.MethodPost, "/auth/login", body, "application/json")
	if err != nil {
		u.render(w, r, "login", PageData{PageTitle: "Sign in", Error: "login failed"})
		return
	}
	if status != http.StatusOK {
		u.render(w, r, "login", PageData{PageTitle: "Sign in", Error: parseAPIError(resp)})
		return
	}
	forwardCookies(w, hdr)
	u.redirect(w, r, "/")
}

func (u *UI) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	_, _, hdr, err := u.apiCall(r, http.MethodPost, "/auth/logout", nil, "")
	if err == nil {
		forwardCookies(w, hdr)
	}
	u.redirect(w, r, "/login")
}

func (u *UI) handleOverview(w http.ResponseWriter, r *http.Request) {
	user, csrf, ok := u.requireAuth(r)
	if !ok {
		u.redirect(w, r, "/login")
		return
	}

	if r.Method == http.MethodPost {
		if !u.mutateModule(w, r, user, csrf) {
			return
		}
		u.redirect(w, r, "/")
		return
	}

	status, statusBody, _, err := u.apiGET(r, "/status")
	if err != nil || status != http.StatusOK {
		u.renderError(w, r, http.StatusInternalServerError, "failed to load status")
		return
	}
	hist, histBody, _, err := u.apiGET(r, "/status/history")
	if err != nil || hist != http.StatusOK {
		u.renderError(w, r, http.StatusInternalServerError, "failed to load history")
		return
	}

	var statusResp map[string]any
	_ = json.Unmarshal(statusBody, &statusResp)
	var histResp struct {
		Samples []map[string]any `json:"samples"`
	}
	_ = json.Unmarshal(histBody, &histResp)

	data := PageData{
		User:      user,
		CSRF:      csrf,
		PageTitle: "Overview",
		Data: map[string]any{
			"status":  statusResp,
			"samples": histResp.Samples,
		},
	}
	u.render(w, r, "overview", data)
}

func (u *UI) mutateModule(w http.ResponseWriter, r *http.Request, user *User, csrf string) bool {
	if !canWriteConfig(user.Role) {
		u.renderError(w, r, http.StatusForbidden, "forbidden")
		return false
	}
	if err := r.ParseForm(); err != nil {
		u.renderError(w, r, http.StatusBadRequest, "invalid form")
		return false
	}
	key := r.FormValue("module")
	enabled := r.FormValue("enabled") == "true"
	if key == "" {
		u.renderError(w, r, http.StatusBadRequest, "module required")
		return false
	}

	r.Header.Set("X-CSRF-Token", csrf)
	defer r.Header.Del("X-CSRF-Token")

	if key == "qfeeds" {
		status, body, _, err := u.apiGET(r, "/qfeeds")
		if err != nil || status != http.StatusOK {
			u.renderError(w, r, http.StatusBadRequest, parseAPIError(body))
			return false
		}
		var qfResp struct {
			Config map[string]any `json:"config"`
		}
		if err := json.Unmarshal(body, &qfResp); err != nil {
			u.renderError(w, r, http.StatusBadRequest, "invalid qfeeds response")
			return false
		}
		cfg := qfResp.Config
		cfg["enabled"] = enabled
		status, putBody, _, err := u.apiPUT(r, "/qfeeds", cfg)
		if err != nil || status != http.StatusOK {
			u.renderError(w, r, http.StatusBadRequest, parseAPIError(putBody))
			return false
		}
		return true
	}

	status, cfgBody, _, err := u.apiGET(r, "/config")
	if err != nil || status != http.StatusOK {
		u.renderError(w, r, http.StatusBadRequest, parseAPIError(cfgBody))
		return false
	}
	var cfgResp struct {
		Live map[string]any `json:"live"`
	}
	if err := json.Unmarshal(cfgBody, &cfgResp); err != nil {
		u.renderError(w, r, http.StatusBadRequest, "invalid config response")
		return false
	}
	live := cfgResp.Live
	if live == nil {
		live = map[string]any{}
	}
	m, ok := live[key].(map[string]any)
	if !ok {
		m = map[string]any{}
		live[key] = m
	}
	m["enabled"] = enabled
	status, putBody, _, err := u.apiPUT(r, "/config", live)
	if err != nil || status != http.StatusOK {
		u.renderError(w, r, http.StatusBadRequest, parseAPIError(putBody))
		return false
	}
	return true
}

func (u *UI) handleUsers(w http.ResponseWriter, r *http.Request) {
	user, csrf, ok := u.requireAuth(r)
	if !ok {
		u.redirect(w, r, "/login")
		return
	}

	if r.Method == http.MethodPost {
		u.handleUserAction(w, r, user, csrf)
		return
	}

	status, body, _, err := u.apiGET(r, "/users")
	if err != nil || status != http.StatusOK {
		u.renderError(w, r, http.StatusInternalServerError, parseAPIError(body))
		return
	}
	var listResp struct {
		Users []map[string]any `json:"users"`
	}
	_ = json.Unmarshal(body, &listResp)

	data := PageData{
		User:      user,
		CSRF:      csrf,
		PageTitle: "Users",
		Data: map[string]any{
			"users": listResp.Users,
		},
	}
	u.render(w, r, "users", data)
}

func (u *UI) handleUserAction(w http.ResponseWriter, r *http.Request, user *User, csrf string) {
	if !canManageUsers(user.Role) {
		u.renderError(w, r, http.StatusForbidden, "forbidden")
		return
	}

	r.Header.Set("X-CSRF-Token", csrf)
	defer r.Header.Del("X-CSRF-Token")

	_ = r.ParseForm()
	action := r.FormValue("action")

	switch action {
	case "create":
		body := map[string]any{
			"username": r.FormValue("username"),
			"password": r.FormValue("password"),
			"role":     r.FormValue("role"),
		}
		status, resp, _, err := u.apiPOST(r, "/users", body)
		if err != nil || status != http.StatusOK {
			u.renderError(w, r, http.StatusBadRequest, parseAPIError(resp))
			return
		}
	case "delete":
		id := r.FormValue("id")
		if id == "" {
			u.renderError(w, r, http.StatusBadRequest, "id required")
			return
		}
		status, resp, _, err := u.apiDELETE(r, "/users/"+id)
		if err != nil || status != http.StatusOK {
			u.renderError(w, r, http.StatusBadRequest, parseAPIError(resp))
			return
		}
	case "toggle":
		id := r.FormValue("id")
		disabled := r.FormValue("disabled") == "true"
		body := map[string]any{"disabled": disabled}
		status, resp, _, err := u.apiPATCH(r, "/users/"+id, body)
		if err != nil || status != http.StatusOK {
			u.renderError(w, r, http.StatusBadRequest, parseAPIError(resp))
			return
		}
	case "role":
		id := r.FormValue("id")
		role := r.FormValue("role")
		body := map[string]any{"role": role}
		status, resp, _, err := u.apiPATCH(r, "/users/"+id, body)
		if err != nil || status != http.StatusOK {
			u.renderError(w, r, http.StatusBadRequest, parseAPIError(resp))
			return
		}
	default:
		u.renderError(w, r, http.StatusBadRequest, "unknown action")
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		u.handleUsers(w, r)
		return
	}
	u.redirect(w, r, "/users")
}

func (u *UI) numberField(m map[string]any, key string) float64 {
	return jsonNumber(m[key])
}

func (u *UI) stringField(m map[string]any, key string) string {
	return jsonString(m[key])
}

func parseHosts(raw string) []string {
	out := []string{}
	for _, part := range strings.Split(raw, ",") {
		s := strings.TrimSpace(part)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func parseLines(raw string) []string {
	out := []string{}
	for _, line := range strings.Split(raw, "\n") {
		s := strings.TrimSpace(line)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func parseOptionalInt(raw string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(raw))
	return n
}
