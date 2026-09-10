// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (u *UI) authed(w http.ResponseWriter, r *http.Request) (*User, string, bool) {
	user, csrf, ok := u.requireAuth(r)
	if !ok {
		u.redirect(w, r, "/login")
		return nil, "", false
	}
	return user, csrf, true
}

func (u *UI) csrfHeader(r *http.Request, csrf string) func() {
	r.Header.Set("X-CSRF-Token", csrf)
	return func() { r.Header.Del("X-CSRF-Token") }
}

func (u *UI) apiCallQ(r *http.Request, method, apiPath string, body any, contentType string, q url.Values) (int, []byte, http.Header, error) {
	old := r.URL.RawQuery
	r.URL.RawQuery = q.Encode()
	status, resp, hdr, err := u.apiCall(r, method, apiPath, body, contentType)
	r.URL.RawQuery = old
	return status, resp, hdr, err
}

func (u *UI) apiRaw(r *http.Request, method, apiPath string, raw []byte, contentType string, q url.Values) (int, []byte, http.Header, error) {
	target := u.basePath + "/api/v1" + apiPath
	if !strings.HasPrefix(target, "/") {
		target = "/" + target
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	inner := r.Clone(ctx)
	inner.Method = method
	inner.URL = &url.URL{Path: target, RawQuery: q.Encode()}
	inner.RequestURI = target
	inner.Body = io.NopCloser(bytes.NewReader(raw))
	inner.ContentLength = int64(len(raw))
	inner.Header = r.Header.Clone()
	if contentType != "" {
		inner.Header.Set("Content-Type", contentType)
	}

	rr := httptest.NewRecorder()
	u.apiMux.ServeHTTP(rr, inner)
	res := rr.Result()
	b, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	return res.StatusCode, b, res.Header, err
}

func (u *UI) apiUpload(r *http.Request, apiPath string, file *multipart.FileHeader, fields map[string]string) (int, []byte, http.Header, error) {
	if file == nil {
		return 0, nil, nil, fmt.Errorf("file required")
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, err := mw.CreateFormFile("file", file.Filename)
	if err != nil {
		return 0, nil, nil, err
	}
	src, err := file.Open()
	if err != nil {
		return 0, nil, nil, err
	}
	if _, err := io.Copy(part, src); err != nil {
		_ = src.Close()
		return 0, nil, nil, err
	}
	_ = src.Close()
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			return 0, nil, nil, err
		}
	}
	if err := mw.Close(); err != nil {
		return 0, nil, nil, err
	}
	return u.apiRaw(r, http.MethodPost, apiPath, buf.Bytes(), mw.FormDataContentType(), url.Values{})
}

func (u *UI) getMap(r *http.Request, apiPath string) (map[string]any, error) {
	status, body, _, err := u.apiGET(r, apiPath)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("%s", parseAPIError(body))
	}
	var out map[string]any
	if len(body) > 0 {
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (u *UI) getJSON(r *http.Request, apiPath string) (any, error) {
	status, body, _, err := u.apiGET(r, apiPath)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("%s", parseAPIError(body))
	}
	var out any
	if len(body) > 0 {
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (u *UI) mutate(w http.ResponseWriter, r *http.Request, method, apiPath string, body any) (map[string]any, bool) {
	status, resp, _, err := u.apiCall(r, method, apiPath, body, "application/json")
	if err != nil || status >= http.StatusBadRequest {
		u.renderError(w, r, status, parseAPIError(resp))
		return nil, false
	}
	var out map[string]any
	if len(resp) > 0 {
		if err := json.Unmarshal(resp, &out); err != nil {
			u.renderError(w, r, http.StatusInternalServerError, "invalid api response")
			return nil, false
		}
	}
	return out, true
}

func (u *UI) renderOrRedirect(w http.ResponseWriter, r *http.Request, name, target string, data PageData) {
	if r.Header.Get("HX-Request") == "true" {
		u.render(w, r, name, data)
		return
	}
	u.redirect(w, r, target)
}

func (u *UI) failAPI(w http.ResponseWriter, r *http.Request, status int, body []byte) {
	if status == 0 {
		status = http.StatusBadGateway
	}
	u.renderError(w, r, status, parseAPIError(body))
}

func pathTail(p, prefix string) string {
	if p == prefix {
		return ""
	}
	if !strings.HasPrefix(p, prefix+"/") {
		return ""
	}
	return strings.Trim(strings.TrimPrefix(p, prefix+"/"), "/")
}

func queryInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func formBool(r *http.Request, name string) bool {
	return r.FormValue(name) == "true" || r.FormValue(name) == "on" || r.FormValue(name) == "1"
}

func formInt(r *http.Request, name string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(r.FormValue(name)))
	return n
}

func formFloat(r *http.Request, name string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(r.FormValue(name)), 64)
	return f
}

func setNested(root map[string]any, path []string, value any) {
	cur := root
	for i, p := range path {
		if i == len(path)-1 {
			cur[p] = value
			return
		}
		next, _ := cur[p].(map[string]any)
		if next == nil {
			next = map[string]any{}
			cur[p] = next
		}
		cur = next
	}
}

func jsonPretty(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func strList(v any) []string {
	out := []string{}
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
	case []string:
		out = append(out, x...)
	}
	return out
}

func joinLines(v any) string {
	return strings.Join(strList(v), "\n")
}

func boolChecked(v any) bool {
	b, _ := v.(bool)
	return b
}

func ruleSlots(p map[string]any, extra int) []map[string]any {
	raw, _ := p["rules"].([]any)
	slots := make([]map[string]any, 0, len(raw)+extra)
	for _, e := range raw {
		m, _ := e.(map[string]any)
		if m == nil {
			continue
		}
		slots = append(slots, map[string]any{
			"type":         jsonString(m["type"]),
			"secret":       "",
			"secret_hash":  jsonString(m["secret_hash"]),
			"cidrs":        joinLines(m["cidrs"]),
			"header_name":  jsonString(m["header_name"]),
			"header_value": jsonString(m["header_value"]),
			"user_agents":  joinLines(m["user_agents"]),
		})
	}
	for len(slots) < len(raw)+extra {
		slots = append(slots, map[string]any{})
	}
	if len(slots) == 0 {
		for i := 0; i < extra; i++ {
			slots = append(slots, map[string]any{})
		}
	}
	return slots
}

func parseAccessRules(r *http.Request, keepHash bool) []map[string]any {
	count := formInt(r, "rule_count")
	if count <= 0 {
		return nil
	}
	out := []map[string]any{}
	for i := 0; i < count; i++ {
		typ := strings.TrimSpace(r.FormValue(fmt.Sprintf("rule_type_%d", i)))
		if typ == "" || typ == "none" {
			continue
		}
		rule := map[string]any{"type": typ}
		switch typ {
		case "password", "pin":
			if s := strings.TrimSpace(r.FormValue(fmt.Sprintf("rule_secret_%d", i))); s != "" {
				rule["secret"] = s
			} else if keepHash {
				if s := strings.TrimSpace(r.FormValue(fmt.Sprintf("rule_secret_hash_%d", i))); s != "" {
					rule["secret_hash"] = s
				} else {
					continue
				}
			} else {
				continue
			}
		case "ip_allowlist":
			if v := parseLines(r.FormValue(fmt.Sprintf("rule_cidrs_%d", i))); len(v) > 0 {
				rule["cidrs"] = v
			} else {
				continue
			}
		case "header":
			name := strings.TrimSpace(r.FormValue(fmt.Sprintf("rule_header_name_%d", i)))
			value := strings.TrimSpace(r.FormValue(fmt.Sprintf("rule_header_value_%d", i)))
			if name == "" || value == "" {
				continue
			}
			rule["header_name"] = name
			rule["header_value"] = value
		case "user_agent":
			if v := parseLines(r.FormValue(fmt.Sprintf("rule_user_agents_%d", i))); len(v) > 0 {
				rule["user_agents"] = v
			} else {
				continue
			}
		default:
			continue
		}
		out = append(out, rule)
	}
	return out
}

func (u *UI) handleSettings(w http.ResponseWriter, r *http.Request) {
	user, csrf, ok := u.authed(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			u.renderError(w, r, http.StatusBadRequest, "invalid form")
			return
		}
		u.handleSettingsPost(w, r, user, csrf)
		return
	}
	u.renderSettings(w, r, user, csrf, nil)
}

func (u *UI) renderSettings(w http.ResponseWriter, r *http.Request, user *User, csrf string, extra map[string]any) {
	me, err := u.getMap(r, "/auth/me")
	if err != nil {
		u.renderError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	sessions, err := u.getMap(r, "/auth/sessions")
	if err != nil {
		u.renderError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	data := map[string]any{
		"me":       me,
		"sessions": sessions["sessions"],
	}
	for k, v := range extra {
		data[k] = v
	}
	u.render(w, r, "settings", PageData{User: user, CSRF: csrf, PageTitle: "Settings", Data: data})
}

func (u *UI) handleSettingsPost(w http.ResponseWriter, r *http.Request, user *User, csrf string) {
	action := r.FormValue("action")
	undo := u.csrfHeader(r, csrf)
	defer undo()

	switch action {
	case "profile":
		out, ok := u.mutate(w, r, http.MethodPatch, "/auth/profile", map[string]any{"username": r.FormValue("username")})
		if !ok {
			return
		}
		u.renderSettings(w, r, user, csrf, map[string]any{"notice": jsonString(out["user"])})
	case "password":
		newPass := r.FormValue("new")
		if newPass == "" || newPass != r.FormValue("confirm") {
			u.renderError(w, r, http.StatusBadRequest, "passwords do not match")
			return
		}
		status, resp, hdr, err := u.apiPOST(r, "/auth/password", map[string]any{"current": r.FormValue("current"), "new": newPass})
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		forwardCookies(w, hdr)
		u.redirect(w, r, "/login")
	case "refresh":
		status, resp, hdr, err := u.apiPOST(r, "/auth/refresh", nil)
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		forwardCookies(w, hdr)
		u.renderSettings(w, r, user, csrf, map[string]any{"notice": "session refreshed"})
	case "revoke":
		status, resp, hdr, err := u.apiDELETE(r, "/auth/sessions/"+r.FormValue("id"))
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		var out struct {
			SignedOut bool `json:"signed_out"`
		}
		_ = json.Unmarshal(resp, &out)
		forwardCookies(w, hdr)
		if out.SignedOut {
			u.redirect(w, r, "/login")
			return
		}
		u.renderSettings(w, r, user, csrf, nil)
	case "revoke_all":
		status, resp, hdr, err := u.apiDELETE(r, "/auth/sessions")
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		var out struct {
			SignedOut bool `json:"signed_out"`
		}
		_ = json.Unmarshal(resp, &out)
		forwardCookies(w, hdr)
		if out.SignedOut {
			u.redirect(w, r, "/login")
			return
		}
		u.renderSettings(w, r, user, csrf, nil)
	default:
		u.renderError(w, r, http.StatusBadRequest, "unknown action")
	}
}

func (u *UI) handleBans(w http.ResponseWriter, r *http.Request) {
	user, csrf, ok := u.authed(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			u.renderError(w, r, http.StatusBadRequest, "invalid form")
			return
		}
		u.handleBansPost(w, r, user, csrf)
		return
	}
	u.renderBans(w, r, user, csrf, nil)
}

func (u *UI) renderBans(w http.ResponseWriter, r *http.Request, user *User, csrf string, extra map[string]any) {
	bans, err := u.getMap(r, "/bans")
	if err != nil {
		u.renderError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	status, body, _, err := u.apiCallQ(r, http.MethodGet, "/threat", nil, "", url.Values{"limit": {"50"}})
	var threat any
	if err == nil && status == http.StatusOK {
		var m map[string]any
		if json.Unmarshal(body, &m) == nil {
			threat = m["matches"]
		}
	}
	data := map[string]any{"bans": bans["bans"], "threat": threat}
	for k, v := range extra {
		data[k] = v
	}
	u.render(w, r, "bans", PageData{User: user, CSRF: csrf, PageTitle: "Bans", Data: data})
}

func (u *UI) handleBansPost(w http.ResponseWriter, r *http.Request, user *User, csrf string) {
	action := r.FormValue("action")
	undo := u.csrfHeader(r, csrf)
	defer undo()

	switch action {
	case "ban":
		key := strings.TrimSpace(r.FormValue("key"))
		if key == "" {
			u.renderError(w, r, http.StatusBadRequest, "key required")
			return
		}
		status, resp, _, err := u.apiPOST(r, "/bans", map[string]any{"key": key})
		if err != nil || status >= http.StatusBadRequest {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderBans(w, r, user, csrf, map[string]any{"notice": "banned " + key})
	case "unban":
		key := strings.TrimSpace(r.FormValue("key"))
		if key == "" {
			u.renderError(w, r, http.StatusBadRequest, "key required")
			return
		}
		status, resp, _, err := u.apiCallQ(r, http.MethodDelete, "/bans", nil, "", url.Values{"key": {key}})
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderBans(w, r, user, csrf, map[string]any{"notice": "unbanned " + key})
	case "share":
		key := strings.TrimSpace(r.FormValue("key"))
		if key == "" {
			u.renderError(w, r, http.StatusBadRequest, "key required")
			return
		}
		kind := r.FormValue("kind")
		if kind == "" {
			kind = "ipv4"
		}
		status, resp, _, err := u.apiPOST(r, "/threat", map[string]any{
			"key_type": kind,
			"key":      key,
			"reason":   r.FormValue("reason"),
			"ttl":      "10m",
			"share":    true,
		})
		if err != nil || status >= http.StatusBadRequest {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderBans(w, r, user, csrf, map[string]any{"notice": "indicator submitted"})
	default:
		u.renderError(w, r, http.StatusBadRequest, "unknown action")
	}
}

func (u *UI) handleBlocklists(w http.ResponseWriter, r *http.Request) {
	user, csrf, ok := u.authed(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			u.renderError(w, r, http.StatusBadRequest, "invalid form")
			return
		}
		u.handleBlocklistsPost(w, r, user, csrf)
		return
	}
	u.renderBlocklists(w, r, user, csrf, nil)
}

func (u *UI) renderBlocklists(w http.ResponseWriter, r *http.Request, user *User, csrf string, extra map[string]any) {
	kind := r.URL.Query().Get("kind")
	if kind == "" {
		kind = "ip"
	}
	stats, err := u.getMap(r, "/blocklists")
	if err != nil {
		u.renderError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	status, body, _, err := u.apiCallQ(r, http.MethodGet, "/blocklists/entries", nil, "", url.Values{"kind": {kind}})
	if err != nil || status != http.StatusOK {
		u.renderError(w, r, http.StatusBadGateway, parseAPIError(body))
		return
	}
	var entries any
	if len(body) > 0 {
		var m map[string]any
		if json.Unmarshal(body, &m) == nil {
			entries = m["entries"]
		}
	}
	data := map[string]any{"stats": stats, "kind": kind, "entries": entries}
	for k, v := range extra {
		data[k] = v
	}
	u.render(w, r, "blocklists", PageData{User: user, CSRF: csrf, PageTitle: "Blocklists", Data: data})
}

func (u *UI) handleBlocklistsPost(w http.ResponseWriter, r *http.Request, user *User, csrf string) {
	action := r.FormValue("action")
	undo := u.csrfHeader(r, csrf)
	defer undo()

	switch action {
	case "reload":
		status, resp, _, err := u.apiPOST(r, "/blocklists/reload", nil)
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderBlocklists(w, r, user, csrf, map[string]any{"notice": "reloaded"})
	case "add":
		kind := r.FormValue("kind")
		value := strings.TrimSpace(r.FormValue("value"))
		if value == "" {
			u.renderError(w, r, http.StatusBadRequest, "value required")
			return
		}
		status, resp, _, err := u.apiPOST(r, "/blocklists/entries", map[string]any{"kind": kind, "value": value})
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderBlocklists(w, r, user, csrf, nil)
	case "edit":
		kind := r.FormValue("kind")
		from := strings.TrimSpace(r.FormValue("from"))
		to := strings.TrimSpace(r.FormValue("to"))
		if from == "" || to == "" {
			u.renderError(w, r, http.StatusBadRequest, "from and to required")
			return
		}
		status, resp, _, err := u.apiPUT(r, "/blocklists/entries", map[string]any{"kind": kind, "from": from, "to": to})
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderBlocklists(w, r, user, csrf, nil)
	case "remove":
		kind := r.FormValue("kind")
		value := strings.TrimSpace(r.FormValue("value"))
		status, resp, _, err := u.apiCallQ(r, http.MethodDelete, "/blocklists/entries", nil, "", url.Values{"kind": {kind}, "value": {value}})
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderBlocklists(w, r, user, csrf, nil)
	default:
		u.renderError(w, r, http.StatusBadRequest, "unknown action")
	}
}

func (u *UI) handleConfig(w http.ResponseWriter, r *http.Request) {
	user, csrf, ok := u.authed(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			u.renderError(w, r, http.StatusBadRequest, "invalid form")
			return
		}
		u.handleConfigPost(w, r, user, csrf)
		return
	}
	if r.URL.Query().Get("export") != "" {
		status, body, _, err := u.apiGET(r, "/config")
		if err != nil || status != http.StatusOK {
			u.renderError(w, r, http.StatusBadGateway, parseAPIError(body))
			return
		}
		var view map[string]any
		if err := json.Unmarshal(body, &view); err != nil {
			u.renderError(w, r, http.StatusBadGateway, "invalid config response")
			return
		}
		live := view["live"]
		out, _ := json.MarshalIndent(live, "", "  ")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="ravenguard-config.json"`)
		_, _ = w.Write(out)
		return
	}
	u.renderConfig(w, r, user, csrf, nil)
}

func (u *UI) renderConfig(w http.ResponseWriter, r *http.Request, user *User, csrf string, extra map[string]any) {
	view, err := u.getMap(r, "/config")
	if err != nil {
		u.renderError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	live := view["live"]
	data := map[string]any{
		"view":           view,
		"live":           live,
		"live_json":      template.HTML(jsonPretty(live)),
		"restart_fields": view["restart_required"],
	}
	for k, v := range extra {
		data[k] = v
	}
	u.render(w, r, "config", PageData{User: user, CSRF: csrf, PageTitle: "Config", Data: data})
}

func (u *UI) handleConfigPost(w http.ResponseWriter, r *http.Request, user *User, csrf string) {
	action := r.FormValue("action")
	undo := u.csrfHeader(r, csrf)
	defer undo()

	switch action {
	case "save":
		payload := strings.TrimSpace(r.FormValue("config"))
		if payload == "" {
			u.renderError(w, r, http.StatusBadRequest, "config required")
			return
		}
		var decoded map[string]any
		if err := json.Unmarshal([]byte(payload), &decoded); err != nil {
			u.renderError(w, r, http.StatusBadRequest, "invalid json: "+err.Error())
			return
		}
		status, resp, _, err := u.apiRaw(r, http.MethodPut, "/config", []byte(payload), "application/json", url.Values{})
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderConfig(w, r, user, csrf, map[string]any{"notice": "configuration saved"})
	case "export":
		status, body, _, err := u.apiGET(r, "/config")
		if err != nil || status != http.StatusOK {
			u.renderError(w, r, http.StatusBadGateway, parseAPIError(body))
			return
		}
		var view map[string]any
		if err := json.Unmarshal(body, &view); err != nil {
			u.renderError(w, r, http.StatusBadGateway, "invalid config response")
			return
		}
		out, _ := json.MarshalIndent(view["live"], "", "  ")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="ravenguard-config.json"`)
		_, _ = w.Write(out)
	default:
		u.renderError(w, r, http.StatusBadRequest, "unknown action")
	}
}

func (u *UI) handleTokens(w http.ResponseWriter, r *http.Request) {
	user, csrf, ok := u.authed(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			u.renderError(w, r, http.StatusBadRequest, "invalid form")
			return
		}
		u.handleTokensPost(w, r, user, csrf)
		return
	}
	u.renderTokens(w, r, user, csrf, nil)
}

func (u *UI) renderTokens(w http.ResponseWriter, r *http.Request, user *User, csrf string, extra map[string]any) {
	out, err := u.getMap(r, "/tokens")
	if err != nil {
		u.renderError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	data := map[string]any{"tokens": out["tokens"]}
	for k, v := range extra {
		data[k] = v
	}
	u.render(w, r, "tokens", PageData{User: user, CSRF: csrf, PageTitle: "Tokens", Data: data})
}

func (u *UI) handleTokensPost(w http.ResponseWriter, r *http.Request, user *User, csrf string) {
	action := r.FormValue("action")
	undo := u.csrfHeader(r, csrf)
	defer undo()

	switch action {
	case "create":
		name := strings.TrimSpace(r.FormValue("name"))
		role := r.FormValue("role")
		expires := r.FormValue("expires_in")
		if name == "" || role == "" {
			u.renderError(w, r, http.StatusBadRequest, "name and role required")
			return
		}
		status, resp, _, err := u.apiPOST(r, "/tokens", map[string]any{"name": name, "role": role, "expires_in": expires})
		if err != nil || status != http.StatusCreated {
			u.failAPI(w, r, status, resp)
			return
		}
		var created map[string]any
		if json.Unmarshal(resp, &created) != nil {
			u.renderError(w, r, http.StatusBadGateway, "invalid token response")
			return
		}
		u.renderTokens(w, r, user, csrf, map[string]any{"created": created})
	case "revoke":
		id := r.FormValue("id")
		if id == "" {
			u.renderError(w, r, http.StatusBadRequest, "id required")
			return
		}
		status, resp, _, err := u.apiDELETE(r, "/tokens/"+id)
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderTokens(w, r, user, csrf, map[string]any{"notice": "token revoked"})
	default:
		u.renderError(w, r, http.StatusBadRequest, "unknown action")
	}
}

func (u *UI) handleAudit(w http.ResponseWriter, r *http.Request) {
	user, csrf, ok := u.authed(w, r)
	if !ok {
		return
	}
	cursor := r.URL.Query().Get("cursor")
	if r.Header.Get("HX-Request") == "true" && cursor != "" {
		u.renderAuditRows(w, r, user, csrf)
		return
	}
	u.renderAudit(w, r, user, csrf)
}

func auditNextCursor(v any) string {
	items, _ := v.([]any)
	if len(items) == 0 {
		return ""
	}
	last, _ := items[len(items)-1].(map[string]any)
	if last == nil {
		return ""
	}
	switch id := last["id"].(type) {
	case float64:
		return strconv.FormatInt(int64(id), 10)
	case json.Number:
		return id.String()
	case string:
		return id
	default:
		return fmt.Sprint(id)
	}
}

func (u *UI) renderAudit(w http.ResponseWriter, r *http.Request, user *User, csrf string) {
	out, err := u.getMap(r, "/audit")
	if err != nil {
		u.renderError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	u.render(w, r, "audit", PageData{User: user, CSRF: csrf, PageTitle: "Audit", Data: map[string]any{"events": out["events"], "next": auditNextCursor(out["events"]), "limit": queryInt(r, "limit", 50)}})
}

func (u *UI) renderAuditRows(w http.ResponseWriter, r *http.Request, user *User, csrf string) {
	out, err := u.getMap(r, "/audit")
	if err != nil {
		u.renderError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	u.render(w, r, "audit-rows", PageData{User: user, CSRF: csrf, PageTitle: "Audit", Data: map[string]any{"events": out["events"], "next": auditNextCursor(out["events"]), "limit": queryInt(r, "limit", 50)}})
}

func (u *UI) handleQFeeds(w http.ResponseWriter, r *http.Request) {
	user, csrf, ok := u.authed(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			u.renderError(w, r, http.StatusBadRequest, "invalid form")
			return
		}
		u.handleQFeedsPost(w, r, user, csrf)
		return
	}
	u.renderQFeeds(w, r, user, csrf, nil)
}

func (u *UI) renderQFeeds(w http.ResponseWriter, r *http.Request, user *User, csrf string, extra map[string]any) {
	view, err := u.getMap(r, "/qfeeds")
	if err != nil {
		u.renderError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	data := map[string]any{"view": view}
	for k, v := range extra {
		data[k] = v
	}
	u.render(w, r, "qfeeds", PageData{User: user, CSRF: csrf, PageTitle: "Q-Feeds", Data: data})
}

func (u *UI) handleQFeedsPost(w http.ResponseWriter, r *http.Request, user *User, csrf string) {
	action := r.FormValue("action")
	undo := u.csrfHeader(r, csrf)
	defer undo()

	switch action {
	case "save":
		payload := map[string]any{
			"enabled":   formBool(r, "enabled"),
			"feeds":     parseLines(r.FormValue("feeds")),
			"refresh":   strings.TrimSpace(r.FormValue("refresh")),
			"on_error":  strings.TrimSpace(r.FormValue("on_error")),
			"base_url":  strings.TrimSpace(r.FormValue("base_url")),
			"limit":     formInt(r, "limit"),
			"api_token": strings.TrimSpace(r.FormValue("api_token")),
		}
		status, resp, _, err := u.apiPUT(r, "/qfeeds", payload)
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderQFeeds(w, r, user, csrf, map[string]any{"notice": "q-feeds saved"})
	case "refresh":
		status, resp, _, err := u.apiPOST(r, "/qfeeds/refresh", nil)
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderQFeeds(w, r, user, csrf, map[string]any{"notice": "refresh started"})
	default:
		u.renderError(w, r, http.StatusBadRequest, "unknown action")
	}
}

func (u *UI) handleUpstreams(w http.ResponseWriter, r *http.Request) {
	user, csrf, ok := u.authed(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			u.renderError(w, r, http.StatusBadRequest, "invalid form")
			return
		}
		u.handleUpstreamsPost(w, r, user, csrf)
		return
	}
	u.renderUpstreams(w, r, user, csrf, nil)
}

func (u *UI) renderUpstreams(w http.ResponseWriter, r *http.Request, user *User, csrf string, extra map[string]any) {
	out, err := u.getMap(r, "/upstreams")
	if err != nil {
		u.renderError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	data := map[string]any{"upstreams": out["upstreams"]}
	id := pathTail(u.trimBase(r.URL.Path), "/upstreams")
	if id != "" {
		status, body, _, err := u.apiGET(r, "/upstreams/"+url.PathEscape(id))
		if err != nil || status != http.StatusOK {
			u.renderError(w, r, http.StatusBadGateway, parseAPIError(body))
			return
		}
		var editing map[string]any
		if json.Unmarshal(body, &editing) == nil {
			data["editing"] = editing
		}
	}
	for k, v := range extra {
		data[k] = v
	}
	u.render(w, r, "upstreams", PageData{User: user, CSRF: csrf, PageTitle: "Upstreams", Data: data})
}

func upstreamPayload(r *http.Request) map[string]any {
	return map[string]any{
		"name":                    strings.TrimSpace(r.FormValue("name")),
		"url":                     strings.TrimSpace(r.FormValue("url")),
		"connect_timeout":         strings.TrimSpace(r.FormValue("connect_timeout")),
		"response_header_timeout": strings.TrimSpace(r.FormValue("response_header_timeout")),
		"idle_conn_timeout":       strings.TrimSpace(r.FormValue("idle_conn_timeout")),
		"max_idle_conns":          formInt(r, "max_idle_conns"),
		"max_idle_conns_per_host": formInt(r, "max_idle_conns_per_host"),
		"max_conns_per_host":      formInt(r, "max_conns_per_host"),
		"flush_interval":          strings.TrimSpace(r.FormValue("flush_interval")),
		"protocol":                strings.TrimSpace(r.FormValue("protocol")),
		"allow_http1":             formBool(r, "allow_http1"),
		"tls_ca_file":             strings.TrimSpace(r.FormValue("tls_ca_file")),
		"tls_client_cert_file":    strings.TrimSpace(r.FormValue("tls_client_cert_file")),
		"tls_client_key_file":     strings.TrimSpace(r.FormValue("tls_client_key_file")),
		"insecure_skip_verify":    formBool(r, "insecure_skip_verify"),
		"set_headers":             parseLines(r.FormValue("set_headers")),
		"health_enabled":          formBool(r, "health_enabled"),
		"health_path":             strings.TrimSpace(r.FormValue("health_path")),
		"health_interval":         strings.TrimSpace(r.FormValue("health_interval")),
		"health_timeout":          strings.TrimSpace(r.FormValue("health_timeout")),
		"health_success_codes":    parseInts(r.FormValue("health_success_codes")),
	}
}

func parseInts(v string) []int {
	out := []int{}
	for _, s := range parseLines(v) {
		if n, err := strconv.Atoi(s); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func (u *UI) handleUpstreamsPost(w http.ResponseWriter, r *http.Request, user *User, csrf string) {
	action := r.FormValue("action")
	undo := u.csrfHeader(r, csrf)
	defer undo()

	switch action {
	case "create":
		payload := upstreamPayload(r)
		if payload["name"] == "" || payload["url"] == "" {
			u.renderError(w, r, http.StatusBadRequest, "name and url required")
			return
		}
		status, resp, _, err := u.apiPOST(r, "/upstreams", payload)
		if err != nil || status >= http.StatusBadRequest {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderUpstreams(w, r, user, csrf, map[string]any{"notice": "upstream created"})
	case "edit":
		id := r.FormValue("id")
		payload := upstreamPayload(r)
		status, resp, _, err := u.apiPUT(r, "/upstreams/"+id, payload)
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderUpstreams(w, r, user, csrf, map[string]any{"notice": "upstream updated"})
	case "delete":
		id := r.FormValue("id")
		status, resp, _, err := u.apiDELETE(r, "/upstreams/"+id)
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderUpstreams(w, r, user, csrf, map[string]any{"notice": "upstream deleted"})
	default:
		u.renderError(w, r, http.StatusBadRequest, "unknown action")
	}
}

func (u *UI) handleRoutes(w http.ResponseWriter, r *http.Request) {
	user, csrf, ok := u.authed(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			u.renderError(w, r, http.StatusBadRequest, "invalid form")
			return
		}
		u.handleRoutesPost(w, r, user, csrf)
		return
	}
	u.renderRoutes(w, r, user, csrf, nil)
}

func (u *UI) renderRoutes(w http.ResponseWriter, r *http.Request, user *User, csrf string, extra map[string]any) {
	routes, err := u.getMap(r, "/routes")
	if err != nil {
		u.renderError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	upstreams, err := u.getMap(r, "/upstreams")
	if err != nil {
		u.renderError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	access, err := u.getMap(r, "/access-policies")
	if err != nil {
		u.renderError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	schemas, err := u.getMap(r, "/api-schemas")
	if err != nil {
		u.renderError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	proxies, err := u.getMap(r, "/proxies")
	if err != nil {
		u.renderError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	data := map[string]any{
		"routes":    routes["routes"],
		"upstreams": upstreams["upstreams"],
		"access":    access["policies"],
		"schemas":   schemas["schemas"],
		"proxies":   proxies["proxies"],
	}
	id := pathTail(u.trimBase(r.URL.Path), "/routes")
	if id != "" {
		status, body, _, err := u.apiGET(r, "/routes/"+url.PathEscape(id))
		if err != nil || status != http.StatusOK {
			u.renderError(w, r, http.StatusBadGateway, parseAPIError(body))
			return
		}
		var editing map[string]any
		if json.Unmarshal(body, &editing) == nil {
			data["editing"] = editing
		}
	}
	for k, v := range extra {
		data[k] = v
	}
	u.render(w, r, "routes", PageData{User: user, CSRF: csrf, PageTitle: "Routes", Data: data})
}

func routePayload(r *http.Request) map[string]any {
	var accessID any
	if s := strings.TrimSpace(r.FormValue("access_policy_id")); s != "" {
		accessID = s
	}
	var schemaID any
	if s := strings.TrimSpace(r.FormValue("openapi_schema_id")); s != "" {
		schemaID = s
	}
	var proxyID any
	if s := strings.TrimSpace(r.FormValue("proxy_id")); s != "" {
		proxyID = s
	}
	return map[string]any{
		"name":              strings.TrimSpace(r.FormValue("name")),
		"enabled":           formBool(r, "enabled"),
		"hosts":             parseHosts(r.FormValue("hosts")),
		"path_prefix":       strings.TrimSpace(r.FormValue("path_prefix")),
		"upstream_id":       strings.TrimSpace(r.FormValue("upstream_id")),
		"strip_prefix":      formBool(r, "strip_prefix"),
		"priority":          formInt(r, "priority"),
		"access_policy_id":  accessID,
		"openapi_schema_id": schemaID,
		"proxy_id":          proxyID,
		"skip_challenge":    formBool(r, "skip_challenge"),
	}
}

func (u *UI) handleRoutesPost(w http.ResponseWriter, r *http.Request, user *User, csrf string) {
	action := r.FormValue("action")
	undo := u.csrfHeader(r, csrf)
	defer undo()

	switch action {
	case "create":
		payload := routePayload(r)
		if payload["name"] == "" || payload["path_prefix"] == "" || payload["upstream_id"] == "" {
			u.renderError(w, r, http.StatusBadRequest, "name, path_prefix, and upstream required")
			return
		}
		status, resp, _, err := u.apiPOST(r, "/routes", payload)
		if err != nil || status >= http.StatusBadRequest {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderRoutes(w, r, user, csrf, map[string]any{"notice": "route created"})
	case "edit":
		id := r.FormValue("id")
		payload := routePayload(r)
		status, resp, _, err := u.apiPUT(r, "/routes/"+id, payload)
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderRoutes(w, r, user, csrf, map[string]any{"notice": "route updated"})
	case "delete":
		id := r.FormValue("id")
		status, resp, _, err := u.apiDELETE(r, "/routes/"+id)
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderRoutes(w, r, user, csrf, map[string]any{"notice": "route deleted"})
	default:
		u.renderError(w, r, http.StatusBadRequest, "unknown action")
	}
}

func (u *UI) handleAccess(w http.ResponseWriter, r *http.Request) {
	user, csrf, ok := u.authed(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			u.renderError(w, r, http.StatusBadRequest, "invalid form")
			return
		}
		u.handleAccessPost(w, r, user, csrf)
		return
	}
	u.renderAccess(w, r, user, csrf, nil)
}

func (u *UI) renderAccess(w http.ResponseWriter, r *http.Request, user *User, csrf string, extra map[string]any) {
	out, err := u.getMap(r, "/access-policies")
	if err != nil {
		u.renderError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	data := map[string]any{"policies": out["policies"]}
	id := pathTail(u.trimBase(r.URL.Path), "/access")
	if id != "" {
		status, body, _, err := u.apiGET(r, "/access-policies/"+url.PathEscape(id))
		if err != nil || status != http.StatusOK {
			u.renderError(w, r, http.StatusBadGateway, parseAPIError(body))
			return
		}
		var editing map[string]any
		if json.Unmarshal(body, &editing) == nil {
			data["editing"] = editing
			data["rules"] = ruleSlots(editing, 3)
		}
	} else {
		data["rules"] = ruleSlots(map[string]any{}, 4)
	}
	for k, v := range extra {
		data[k] = v
	}
	u.render(w, r, "access", PageData{User: user, CSRF: csrf, PageTitle: "Access", Data: data})
}

func (u *UI) handleAccessPost(w http.ResponseWriter, r *http.Request, user *User, csrf string) {
	action := r.FormValue("action")
	undo := u.csrfHeader(r, csrf)
	defer undo()

	switch action {
	case "create":
		rules := parseAccessRules(r, false)
		if len(rules) == 0 {
			u.renderError(w, r, http.StatusBadRequest, "at least one rule required")
			return
		}
		payload := map[string]any{"name": strings.TrimSpace(r.FormValue("name")), "mode": r.FormValue("mode"), "cookie_ttl": strings.TrimSpace(r.FormValue("cookie_ttl")), "rules": rules}
		status, resp, _, err := u.apiPOST(r, "/access-policies", payload)
		if err != nil || status >= http.StatusBadRequest {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderAccess(w, r, user, csrf, map[string]any{"notice": "policy created"})
	case "edit":
		id := r.FormValue("id")
		rules := parseAccessRules(r, true)
		if len(rules) == 0 {
			u.renderError(w, r, http.StatusBadRequest, "at least one rule required")
			return
		}
		payload := map[string]any{"name": strings.TrimSpace(r.FormValue("name")), "mode": r.FormValue("mode"), "cookie_ttl": strings.TrimSpace(r.FormValue("cookie_ttl")), "rules": rules}
		status, resp, _, err := u.apiPUT(r, "/access-policies/"+id, payload)
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderAccess(w, r, user, csrf, map[string]any{"notice": "policy updated"})
	case "delete":
		id := r.FormValue("id")
		status, resp, _, err := u.apiDELETE(r, "/access-policies/"+id)
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderAccess(w, r, user, csrf, map[string]any{"notice": "policy deleted"})
	default:
		u.renderError(w, r, http.StatusBadRequest, "unknown action")
	}
}

func (u *UI) handleSchemas(w http.ResponseWriter, r *http.Request) {
	user, csrf, ok := u.authed(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			u.renderError(w, r, http.StatusBadRequest, "invalid form")
			return
		}
		u.handleSchemasPost(w, r, user, csrf)
		return
	}
	u.renderSchemas(w, r, user, csrf, nil)
}

func (u *UI) renderSchemas(w http.ResponseWriter, r *http.Request, user *User, csrf string, extra map[string]any) {
	out, err := u.getMap(r, "/api-schemas")
	if err != nil {
		u.renderError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	data := map[string]any{"schemas": out["schemas"]}
	id := pathTail(u.trimBase(r.URL.Path), "/schemas")
	if id != "" {
		status, body, _, err := u.apiGET(r, "/api-schemas/"+url.PathEscape(id))
		if err != nil || status != http.StatusOK {
			u.renderError(w, r, http.StatusBadGateway, parseAPIError(body))
			return
		}
		var editing map[string]any
		if json.Unmarshal(body, &editing) == nil {
			if spec, ok := editing["spec_text"].(string); ok {
				editing["spec_text"] = template.HTML(spec)
			}
			data["editing"] = editing
		}
	}
	for k, v := range extra {
		data[k] = v
	}
	u.render(w, r, "schemas", PageData{User: user, CSRF: csrf, PageTitle: "API schemas", Data: data})
}

func (u *UI) handleSchemasPost(w http.ResponseWriter, r *http.Request, user *User, csrf string) {
	action := r.FormValue("action")
	undo := u.csrfHeader(r, csrf)
	defer undo()

	switch action {
	case "create":
		payload := map[string]any{"name": strings.TrimSpace(r.FormValue("name")), "mode": r.FormValue("mode"), "spec_text": r.FormValue("spec_text")}
		status, resp, _, err := u.apiPOST(r, "/api-schemas", payload)
		if err != nil || status >= http.StatusBadRequest {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderSchemas(w, r, user, csrf, map[string]any{"notice": "schema created"})
	case "edit":
		id := r.FormValue("id")
		payload := map[string]any{"name": strings.TrimSpace(r.FormValue("name")), "mode": r.FormValue("mode"), "spec_text": r.FormValue("spec_text")}
		status, resp, _, err := u.apiPUT(r, "/api-schemas/"+id, payload)
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderSchemas(w, r, user, csrf, map[string]any{"notice": "schema updated"})
	case "delete":
		id := r.FormValue("id")
		status, resp, _, err := u.apiDELETE(r, "/api-schemas/"+id)
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderSchemas(w, r, user, csrf, map[string]any{"notice": "schema deleted"})
	default:
		u.renderError(w, r, http.StatusBadRequest, "unknown action")
	}
}

func (u *UI) handleCerts(w http.ResponseWriter, r *http.Request) {
	user, csrf, ok := u.authed(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			u.renderError(w, r, http.StatusBadRequest, "invalid form")
			return
		}
		u.handleCertsPost(w, r, user, csrf)
		return
	}
	u.renderCerts(w, r, user, csrf, nil)
}

func (u *UI) renderCerts(w http.ResponseWriter, r *http.Request, user *User, csrf string, extra map[string]any) {
	status, body, _, err := u.apiGET(r, "/certs")
	if err != nil || status != http.StatusOK {
		u.renderError(w, r, http.StatusBadGateway, parseAPIError(body))
		return
	}
	var out map[string]any
	var certs any
	if json.Unmarshal(body, &out) == nil {
		certs = out["certs"]
	}
	data := map[string]any{"certs": certs}
	host := pathTail(u.trimBase(r.URL.Path), "/certs")
	if host != "" {
		status, body, _, err := u.apiGET(r, "/certs/"+url.PathEscape(host))
		if err != nil || status != http.StatusOK {
			u.renderError(w, r, http.StatusBadGateway, parseAPIError(body))
			return
		}
		var detail map[string]any
		if json.Unmarshal(body, &detail) == nil {
			data["detail"] = detail
		}
	}
	for k, v := range extra {
		data[k] = v
	}
	u.render(w, r, "certs", PageData{User: user, CSRF: csrf, PageTitle: "Certificates", Data: data})
}

func (u *UI) handleCertsPost(w http.ResponseWriter, r *http.Request, user *User, csrf string) {
	action := r.FormValue("action")
	undo := u.csrfHeader(r, csrf)
	defer undo()

	switch action {
	case "generate":
		host := strings.TrimSpace(r.FormValue("host"))
		if host == "" {
			u.renderError(w, r, http.StatusBadRequest, "host required")
			return
		}
		payload := map[string]any{"validity": r.FormValue("validity"), "dns_names": parseHosts(r.FormValue("dns_names"))}
		status, resp, _, err := u.apiPOST(r, "/certs/"+url.PathEscape(host)+"/generate", payload)
		if err != nil || status >= http.StatusBadRequest {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderCerts(w, r, user, csrf, map[string]any{"notice": "certificate generated for " + host})
	case "upload":
		host := strings.TrimSpace(r.FormValue("host"))
		certPEM := r.FormValue("cert_pem")
		keyPEM := r.FormValue("key_pem")
		if host == "" || certPEM == "" || keyPEM == "" {
			u.renderError(w, r, http.StatusBadRequest, "host, cert_pem, and key_pem required")
			return
		}
		payload := map[string]any{"cert_pem": certPEM, "key_pem": keyPEM}
		status, resp, _, err := u.apiPUT(r, "/certs/"+url.PathEscape(host), payload)
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderCerts(w, r, user, csrf, map[string]any{"notice": "certificate uploaded for " + host})
	case "renew":
		host := strings.TrimSpace(r.FormValue("host"))
		status, resp, _, err := u.apiPOST(r, "/certs/"+url.PathEscape(host)+"/renew", nil)
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderCerts(w, r, user, csrf, map[string]any{"notice": "certificate renewal queued for " + host})
	case "delete":
		host := strings.TrimSpace(r.FormValue("host"))
		status, resp, _, err := u.apiDELETE(r, "/certs/"+url.PathEscape(host))
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderCerts(w, r, user, csrf, map[string]any{"notice": "certificate deleted for " + host})
	case "manage":
		hosts := parseHosts(r.FormValue("hosts"))
		if len(hosts) == 0 {
			u.renderError(w, r, http.StatusBadRequest, "hosts required")
			return
		}
		status, resp, _, err := u.apiPOST(r, "/certs/manage", map[string]any{"hosts": hosts})
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderCerts(w, r, user, csrf, map[string]any{"notice": "acme manage request submitted"})
	default:
		u.renderError(w, r, http.StatusBadRequest, "unknown action")
	}
}

func (u *UI) handleLogs(w http.ResponseWriter, r *http.Request) {
	user, csrf, ok := u.authed(w, r)
	if !ok {
		return
	}
	out, err := u.getMap(r, "/logs")
	if err != nil {
		u.renderError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	u.render(w, r, "logs", PageData{User: user, CSRF: csrf, PageTitle: "Logs", Data: map[string]any{"logs": out["logs"], "limit": queryInt(r, "limit", 100), "level": r.URL.Query().Get("level"), "q": r.URL.Query().Get("q")}})
}

func (u *UI) handleRequests(w http.ResponseWriter, r *http.Request) {
	user, csrf, ok := u.authed(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			u.renderError(w, r, http.StatusBadRequest, "invalid form")
			return
		}
		if r.FormValue("action") == "lookup" {
			ray := strings.TrimSpace(r.FormValue("ray"))
			if ray == "" {
				u.renderError(w, r, http.StatusBadRequest, "ray required")
				return
			}
			q := url.Values{}
			if v := strings.TrimSpace(r.FormValue("proxy_id")); v != "" {
				q.Set("proxy_id", v)
			}
			target := "/requests/" + url.PathEscape(ray)
			if len(q) > 0 {
				target += "?" + q.Encode()
			}
			u.redirect(w, r, target)
			return
		}
	}
	u.renderRequests(w, r, user, csrf, nil)
}

func (u *UI) renderRequests(w http.ResponseWriter, r *http.Request, user *User, csrf string, extra map[string]any) {
	out, err := u.getMap(r, "/requests")
	if err != nil {
		u.renderError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	proxies, err := u.getMap(r, "/proxies")
	if err != nil {
		u.renderError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	data := map[string]any{
		"requests": out["requests"],
		"proxies":  proxies["proxies"],
		"proxy_id": r.URL.Query().Get("proxy_id"),
		"limit":    queryInt(r, "limit", 50),
	}
	ray := pathTail(u.trimBase(r.URL.Path), "/requests")
	if ray != "" {
		status, body, _, err := u.apiGET(r, "/requests/"+url.PathEscape(ray))
		if err != nil || status != http.StatusOK {
			u.renderError(w, r, http.StatusBadGateway, parseAPIError(body))
			return
		}
		var detail map[string]any
		if json.Unmarshal(body, &detail) == nil {
			data["detail"] = detail
			data["ray"] = ray
		}
	}
	for k, v := range extra {
		data[k] = v
	}
	u.render(w, r, "requests", PageData{User: user, CSRF: csrf, PageTitle: "Requests", Data: data})
}

func (u *UI) handleAppearance(w http.ResponseWriter, r *http.Request) {
	user, csrf, ok := u.authed(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseMultipartForm(8 << 20); err != nil {
			if err := r.ParseForm(); err != nil {
				u.renderError(w, r, http.StatusBadRequest, "invalid form")
				return
			}
		}
		u.handleAppearancePost(w, r, user, csrf)
		return
	}
	u.renderAppearance(w, r, user, csrf, nil)
}

func (u *UI) renderAppearance(w http.ResponseWriter, r *http.Request, user *User, csrf string, extra map[string]any) {
	view, err := u.getMap(r, "/config")
	if err != nil {
		u.renderError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	live, _ := view["live"].(map[string]any)
	ui, _ := live["ui"].(map[string]any)
	stealth, _ := live["stealth"].(map[string]any)
	if ui == nil {
		ui = map[string]any{}
	}
	if stealth == nil {
		stealth = map[string]any{}
	}
	ui["custom_css_raw"] = template.HTML(jsonString(ui["custom_css"]))
	data := map[string]any{
		"view":    view,
		"live":    live,
		"ui":      ui,
		"stealth": stealth,
	}
	for k, v := range extra {
		data[k] = v
	}
	u.render(w, r, "appearance", PageData{User: user, CSRF: csrf, PageTitle: "Appearance", Data: data})
}

func appearanceMaps(r *http.Request) (map[string]any, map[string]any) {
	uiFields := []string{
		"brand", "status_text", "logo_url", "favicon_url", "theme_color", "background",
		"foreground", "accent", "font_sans", "font_mono", "challenge_title",
		"challenge_subtitle", "block_title", "rate_limit_title", "upstream_title",
		"error_title", "footer_text", "contact", "custom_css", "description", "lang",
		"robots", "privacy_notice_url", "og_image", "ray_label",
	}
	uiMap := map[string]any{}
	for _, f := range uiFields {
		uiMap[f] = r.FormValue("ui." + f)
	}
	stealth := map[string]any{"hide_brand_mark": formBool(r, "stealth.hide_brand_mark")}
	if v := strings.TrimSpace(r.FormValue("stealth.ray_header")); v != "" {
		stealth["ray_header"] = v
	}
	return uiMap, stealth
}

func (u *UI) handleAppearancePost(w http.ResponseWriter, r *http.Request, user *User, csrf string) {
	action := r.FormValue("action")
	undo := u.csrfHeader(r, csrf)
	defer undo()

	switch action {
	case "save":
		uiMap, stealth := appearanceMaps(r)
		status, body, _, err := u.apiGET(r, "/config")
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, body)
			return
		}
		var view map[string]any
		if json.Unmarshal(body, &view) != nil {
			u.renderError(w, r, http.StatusBadGateway, "invalid config response")
			return
		}
		live, _ := view["live"].(map[string]any)
		if live == nil {
			live = map[string]any{}
		}
		live["ui"] = uiMap
		live["stealth"] = stealth
		status, resp, _, err := u.apiPUT(r, "/config", live)
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderAppearance(w, r, user, csrf, map[string]any{"notice": "appearance saved"})
	case "preview":
		uiMap, stealth := appearanceMaps(r)
		page := r.FormValue("page")
		if page == "" {
			page = "challenge"
		}
		status, body, _, err := u.apiCallQ(r, http.MethodPost, "/appearance/preview", map[string]any{"ui": uiMap, "stealth": stealth}, "application/json", url.Values{"page": {page}})
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, body)
			return
		}
		u.renderAppearance(w, r, user, csrf, map[string]any{"preview": string(body), "preview_page": page})
	case "upload":
		kind := r.FormValue("kind")
		var file *multipart.FileHeader
		if r.MultipartForm != nil && len(r.MultipartForm.File["file"]) > 0 {
			file = r.MultipartForm.File["file"][0]
		}
		if file == nil {
			u.renderError(w, r, http.StatusBadRequest, "file required")
			return
		}
		status, resp, _, err := u.apiUpload(r, "/appearance/assets", file, map[string]string{"kind": kind})
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		var out map[string]any
		if json.Unmarshal(resp, &out) == nil {
			notice := "asset uploaded"
			if u, ok := out["url"].(string); ok {
				notice = kind + " updated: " + u
			}
			u.renderAppearance(w, r, user, csrf, map[string]any{"notice": notice})
			return
		}
		u.renderAppearance(w, r, user, csrf, map[string]any{"notice": "asset uploaded"})
	default:
		u.renderError(w, r, http.StatusBadRequest, "unknown action")
	}
}

func (u *UI) handleThreatIntel(w http.ResponseWriter, r *http.Request) {
	user, csrf, ok := u.authed(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			u.renderError(w, r, http.StatusBadRequest, "invalid form")
			return
		}
		u.handleThreatIntelPost(w, r, user, csrf)
		return
	}
	u.renderThreatIntel(w, r, user, csrf, nil)
}

func (u *UI) renderThreatIntel(w http.ResponseWriter, r *http.Request, user *User, csrf string, extra map[string]any) {
	cfg, err := u.getMap(r, "/threatintel/config")
	if err != nil {
		u.renderError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	data := map[string]any{"cfg": cfg}
	for k, v := range extra {
		data[k] = v
	}
	u.render(w, r, "threatintel", PageData{User: user, CSRF: csrf, PageTitle: "Threat intel", Data: data})
}

func threatConfigPayload(r *http.Request) map[string]any {
	payload := map[string]any{"export_raw_ip": formBool(r, "export_raw_ip")}
	if v := strings.TrimSpace(r.FormValue("ingest_urls")); v != "" {
		payload["ingest_urls"] = parseLines(v)
	}
	if v := strings.TrimSpace(r.FormValue("ingest_interval")); v != "" {
		payload["ingest_interval"] = v
	}
	if v := strings.TrimSpace(r.FormValue("default_ttl")); v != "" {
		payload["default_ttl"] = v
	}
	if v := strings.TrimSpace(r.FormValue("abuseipdb_min_confidence")); v != "" {
		payload["abuseipdb_min_confidence"] = formInt(r, "abuseipdb_min_confidence")
	}
	if v := strings.TrimSpace(r.FormValue("abuseipdb_limit")); v != "" {
		payload["abuseipdb_limit"] = formInt(r, "abuseipdb_limit")
	}
	if v := strings.TrimSpace(r.FormValue("misp_url")); v != "" {
		payload["misp_url"] = v
	}
	if v := strings.TrimSpace(r.FormValue("misp_key")); v != "" {
		payload["misp_key"] = v
	}
	if v := strings.TrimSpace(r.FormValue("export_token")); v != "" {
		payload["export_token"] = v
	}
	if v := strings.TrimSpace(r.FormValue("abuseipdb_key")); v != "" {
		payload["abuseipdb_key"] = v
	}
	return payload
}

func (u *UI) handleThreatIntelPost(w http.ResponseWriter, r *http.Request, user *User, csrf string) {
	action := r.FormValue("action")
	undo := u.csrfHeader(r, csrf)
	defer undo()

	switch action {
	case "save":
		status, resp, _, err := u.apiPUT(r, "/threatintel/config", threatConfigPayload(r))
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderThreatIntel(w, r, user, csrf, map[string]any{"notice": "threat intel config saved"})
	case "ingest":
		format := r.FormValue("format")
		content := r.FormValue("content")
		if strings.TrimSpace(content) == "" {
			u.renderError(w, r, http.StatusBadRequest, "content required")
			return
		}
		ct := "text/csv"
		if format == "stix" {
			ct = "application/json"
		}
		status, resp, _, err := u.apiRaw(r, http.MethodPost, "/threatintel/ingest", []byte(content), ct, url.Values{"format": {format}})
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		var out map[string]any
		_ = json.Unmarshal(resp, &out)
		u.renderThreatIntel(w, r, user, csrf, map[string]any{"notice": "ingested", "ingest_result": out})
	case "ingest_url":
		format := r.FormValue("format")
		urlValue := strings.TrimSpace(r.FormValue("url"))
		if urlValue == "" {
			u.renderError(w, r, http.StatusBadRequest, "url required")
			return
		}
		status, resp, _, err := u.apiPOST(r, "/threatintel/ingest/url", map[string]any{"url": urlValue, "format": format})
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderThreatIntel(w, r, user, csrf, map[string]any{"notice": "url ingest queued"})
	case "abuse_sync":
		status, resp, _, err := u.apiPOST(r, "/threatintel/abuseipdb/sync", nil)
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderThreatIntel(w, r, user, csrf, map[string]any{"notice": "abuseipdb sync queued"})
	case "misp_sync":
		status, resp, _, err := u.apiPOST(r, "/threatintel/misp/sync", nil)
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderThreatIntel(w, r, user, csrf, map[string]any{"notice": "misp sync queued"})
	case "report":
		payload := map[string]any{
			"ip":          strings.TrimSpace(r.FormValue("ip")),
			"comment":     strings.TrimSpace(r.FormValue("comment")),
			"confirm_raw": formBool(r, "confirm_raw"),
			"categories":  parseInts(r.FormValue("categories")),
		}
		if payload["ip"] == "" {
			u.renderError(w, r, http.StatusBadRequest, "ip required")
			return
		}
		status, resp, _, err := u.apiPOST(r, "/threatintel/abuseipdb/report", payload)
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderThreatIntel(w, r, user, csrf, map[string]any{"notice": "abuseipdb report submitted"})
	default:
		u.renderError(w, r, http.StatusBadRequest, "unknown action")
	}
}

func (u *UI) handleProxies(w http.ResponseWriter, r *http.Request) {
	user, csrf, ok := u.authed(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			u.renderError(w, r, http.StatusBadRequest, "invalid form")
			return
		}
		u.handleProxiesPost(w, r, user, csrf)
		return
	}
	u.renderProxies(w, r, user, csrf, nil)
}

func (u *UI) renderProxies(w http.ResponseWriter, r *http.Request, user *User, csrf string, extra map[string]any) {
	out, err := u.getMap(r, "/proxies")
	if err != nil {
		u.renderError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	data := map[string]any{
		"proxies":    out["proxies"],
		"hub_url":    out["hub_url"],
		"hub_pubkey": out["hub_pubkey"],
	}
	for k, v := range extra {
		data[k] = v
	}
	u.render(w, r, "proxies", PageData{User: user, CSRF: csrf, PageTitle: "Proxies", Data: data})
}

func (u *UI) handleProxiesPost(w http.ResponseWriter, r *http.Request, user *User, csrf string) {
	action := r.FormValue("action")
	undo := u.csrfHeader(r, csrf)
	defer undo()

	switch action {
	case "create":
		payload := map[string]any{
			"name":        strings.TrimSpace(r.FormValue("name")),
			"tags":        parseHosts(r.FormValue("tags")),
			"public_ipv4": strings.TrimSpace(r.FormValue("public_ipv4")),
			"public_ipv6": strings.TrimSpace(r.FormValue("public_ipv6")),
			"universal":   formBool(r, "universal"),
		}
		if payload["name"] == "" {
			u.renderError(w, r, http.StatusBadRequest, "name required")
			return
		}
		status, resp, _, err := u.apiPOST(r, "/proxies", payload)
		if err != nil || status != http.StatusCreated {
			u.failAPI(w, r, status, resp)
			return
		}
		var out map[string]any
		if json.Unmarshal(resp, &out) != nil {
			u.renderError(w, r, http.StatusBadGateway, "invalid proxy response")
			return
		}
		u.renderProxies(w, r, user, csrf, map[string]any{"notice": "proxy created", "enroll": out})
	case "rotate":
		id := r.FormValue("id")
		status, resp, _, err := u.apiPOST(r, "/proxies/"+id+"/rotate-token", nil)
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		var out map[string]any
		_ = json.Unmarshal(resp, &out)
		u.renderProxies(w, r, user, csrf, map[string]any{"notice": "token rotated", "enroll": out})
	case "push":
		id := r.FormValue("id")
		status, resp, _, err := u.apiPOST(r, "/proxies/"+id+"/push", nil)
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderProxies(w, r, user, csrf, map[string]any{"notice": "push sent"})
	case "delete":
		id := r.FormValue("id")
		status, resp, _, err := u.apiDELETE(r, "/proxies/"+id)
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderProxies(w, r, user, csrf, map[string]any{"notice": "proxy deleted"})
	case "status":
		id := r.FormValue("id")
		status, resp, _, err := u.apiGET(r, "/proxies/"+id+"/status")
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		var out map[string]any
		_ = json.Unmarshal(resp, &out)
		u.renderProxies(w, r, user, csrf, map[string]any{"status_for": id, "status": out})
	default:
		u.renderError(w, r, http.StatusBadRequest, "unknown action")
	}
}

func (u *UI) handleMigrations(w http.ResponseWriter, r *http.Request) {
	user, csrf, ok := u.authed(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			u.renderError(w, r, http.StatusBadRequest, "invalid form")
			return
		}
		u.handleMigrationsPost(w, r, user, csrf)
		return
	}
	u.renderMigrations(w, r, user, csrf, nil)
}

func (u *UI) renderMigrations(w http.ResponseWriter, r *http.Request, user *User, csrf string, extra map[string]any) {
	proxies, err := u.getMap(r, "/proxies")
	if err != nil {
		u.renderError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	routes, err := u.getMap(r, "/routes")
	if err != nil {
		u.renderError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	migrations, err := u.getMap(r, "/migrations")
	if err != nil {
		u.renderError(w, r, http.StatusBadGateway, err.Error())
		return
	}
	data := map[string]any{
		"proxies":    proxies["proxies"],
		"routes":     routes["routes"],
		"migrations": migrations["migrations"],
	}
	id := pathTail(u.trimBase(r.URL.Path), "/migrations")
	if id != "" {
		status, body, _, err := u.apiGET(r, "/migrations/"+url.PathEscape(id))
		if err != nil || status != http.StatusOK {
			u.renderError(w, r, http.StatusBadGateway, parseAPIError(body))
			return
		}
		var detail map[string]any
		if json.Unmarshal(body, &detail) == nil {
			data["active"] = detail
		}
	}
	for k, v := range extra {
		data[k] = v
	}
	u.render(w, r, "migrations", PageData{User: user, CSRF: csrf, PageTitle: "Move services", Data: data})
}

func (u *UI) handleMigrationsPost(w http.ResponseWriter, r *http.Request, user *User, csrf string) {
	action := r.FormValue("action")
	undo := u.csrfHeader(r, csrf)
	defer undo()

	switch action {
	case "create":
		from := strings.TrimSpace(r.FormValue("from_proxy_id"))
		to := strings.TrimSpace(r.FormValue("to_proxy_id"))
		routeIDs := r.PostForm["route_ids"]
		if from == "" || to == "" || len(routeIDs) == 0 {
			u.renderError(w, r, http.StatusBadRequest, "from proxy, to proxy, and routes required")
			return
		}
		payload := map[string]any{"from_proxy_id": from, "to_proxy_id": to, "route_ids": routeIDs}
		status, resp, _, err := u.apiPOST(r, "/migrations", payload)
		if err != nil || status != http.StatusCreated {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderMigrations(w, r, user, csrf, map[string]any{"notice": "migration created"})
	case "prep", "complete", "abort":
		id := r.FormValue("id")
		if id == "" {
			u.renderError(w, r, http.StatusBadRequest, "id required")
			return
		}
		status, resp, _, err := u.apiPOST(r, "/migrations/"+id+"/"+action, nil)
		if err != nil || status != http.StatusOK {
			u.failAPI(w, r, status, resp)
			return
		}
		u.renderMigrations(w, r, user, csrf, map[string]any{"notice": "migration " + action})
	default:
		u.renderError(w, r, http.StatusBadRequest, "unknown action")
	}
}
