// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ui

import (
	"encoding/json"
	"fmt"
	"html/template"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func maxAny(vals ...any) float64 {
	var m float64
	for _, v := range vals {
		n := jsonNumber(v)
		if n > m {
			m = n
		}
	}
	return m
}

func gtAny(a, b any) bool {
	return jsonNumber(a) > jsonNumber(b)
}

func formatBytes(n float64) string {
	if !isFinite(n) || n < 0 {
		return "0 B"
	}
	units := []string{"B", "KB", "MB", "GB", "TB"}
	v := n
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	digits := 0
	if i > 0 {
		if v >= 10 {
			digits = 1
		} else {
			digits = 2
		}
	}
	return fmt.Sprintf("%.*f %s", digits, v, units[i])
}

func formatPct(n float64) string {
	if !isFinite(n) {
		return "0%"
	}
	a := math.Abs(n)
	if a >= 10 {
		return fmt.Sprintf("%.0f%%", n)
	}
	return fmt.Sprintf("%.1f%%", n)
}

func formatNum(n float64) string {
	if !isFinite(n) {
		return "0"
	}
	sign := ""
	if n < 0 {
		sign = "-"
	}
	x := math.Abs(n)
	switch {
	case x >= 1_000_000_000:
		return fmt.Sprintf("%s%.1fB", sign, x/1_000_000_000)
	case x >= 1_000_000:
		return fmt.Sprintf("%s%.1fM", sign, x/1_000_000)
	case x >= 10_000:
		return fmt.Sprintf("%s%.1fk", sign, x/1000)
	}
	return fmt.Sprintf("%s%s", sign, strconv.FormatInt(int64(math.Round(x)), 10))
}

func formatUptime(seconds float64) string {
	d := int(seconds / 86400)
	h := int((seconds - float64(d*86400)) / 3600)
	m := int((seconds - float64(d*86400) - float64(h*3600)) / 60)
	parts := []string{}
	if d > 0 {
		parts = append(parts, fmt.Sprintf("%dd", d))
	}
	if d > 0 || h > 0 {
		parts = append(parts, fmt.Sprintf("%dh", h))
	}
	parts = append(parts, fmt.Sprintf("%dm", m))
	return strings.Join(parts, " ")
}

func formatNs(ns float64) string {
	if !isFinite(ns) || ns <= 0 {
		return "0 ns"
	}
	if ns < 1000 {
		return fmt.Sprintf("%.0f ns", ns)
	}
	if ns < 1_000_000 {
		return fmt.Sprintf("%.1f us", ns/1000)
	}
	return fmt.Sprintf("%.2f ms", ns/1_000_000)
}

func formatTime(t string) string {
	ts, err := time.Parse(time.RFC3339Nano, t)
	if err != nil {
		return t
	}
	return ts.Format("2006-01-02 15:04:05")
}

func isFinite(n float64) bool {
	return !math.IsNaN(n) && !math.IsInf(n, 0)
}

func roleRank(role string) int {
	switch role {
	case "owner":
		return 3
	case "admin":
		return 2
	case "viewer":
		return 1
	}
	return 0
}

func roleAtLeast(role, min string) bool {
	return roleRank(role) >= roleRank(min)
}

func canWriteOps(role string) bool {
	return roleAtLeast(role, "admin")
}

func canWriteConfig(role string) bool {
	return roleAtLeast(role, "admin")
}

func canManageUsers(role string) bool {
	return roleAtLeast(role, "admin")
}

func canManageOwners(role string) bool {
	return role == "owner"
}

type navLink struct {
	Path  string
	Label string
	Needs string
}

var links = []navLink{
	{"/", "Overview", ""},
	{"/proxies", "Proxies", ""},
	{"/migrations", "Move services", ""},
	{"/upstreams", "Upstreams", ""},
	{"/routes", "Routes", ""},
	{"/access", "Access", ""},
	{"/schemas", "API schemas", ""},
	{"/certs", "Certificates", ""},
	{"/requests", "Requests", ""},
	{"/logs", "Logs", ""},
	{"/bans", "Bans", ""},
	{"/threatintel", "Threat intel", ""},
	{"/blocklists", "Blocklists", ""},
	{"/qfeeds", "Q-Feeds", ""},
	{"/appearance", "Appearance", ""},
	{"/config", "Config", ""},
	{"/users", "Users", "manageUsers"},
	{"/tokens", "Tokens", ""},
	{"/audit", "Audit", ""},
}

func navLinks() []navLink { return links }

func navHref(base, p string) string {
	if p == "/" {
		return base + "/"
	}
	return base + p
}

func navActive(pathname, href string) bool {
	if href == "/" || href == "" {
		return pathname == "/" || pathname == ""
	}
	return pathname == href || strings.HasPrefix(pathname, href+"/")
}

func navVisible(link navLink, role string) bool {
	if link.Needs == "manageUsers" {
		return canManageUsers(role)
	}
	return true
}

func statusTone(pct float64) string {
	if pct >= 85 {
		return "bad"
	}
	if pct >= 60 {
		return "warn"
	}
	return "ok"
}

func moduleState(status PageData, key string) string {
	d, _ := status.Data.(map[string]any)
	enabled, _ := d[key+"_enabled"].(bool)
	if !enabled {
		return "off"
	}
	if key == "qfeeds" {
		failed, _ := d["qfeeds_failed"].(bool)
		if failed {
			return "degraded"
		}
	}
	return "on"
}

func sparklineSVG(values []float64, width, height int, stroke string) template.HTML {
	if len(values) == 0 {
		return template.HTML(fmt.Sprintf(`<svg viewBox="0 0 %d %d" width="%d" height="%d" class="sparkline"></svg>`, width, height, width, height))
	}
	minV, maxV := values[0], values[0]
	for _, v := range values {
		if v < minV {
			minV = v
		}
		if v > maxV {
			maxV = v
		}
	}
	if maxV == minV {
		maxV = minV + 1
	}
	points := make([]string, len(values))
	for i, v := range values {
		x := float64(i) * float64(width) / float64(len(values)-1)
		y := float64(height) - ((v-minV)/(maxV-minV))*float64(height-4) - 2
		points[i] = fmt.Sprintf("%.1f,%.1f", x, y)
	}
	polyline := strings.Join(points, " ")
	area := polyline + fmt.Sprintf(" %d,%.1f 0,%.1f", width, float64(height), float64(height))
	return template.HTML(fmt.Sprintf(
		`<svg viewBox="0 0 %d %d" width="%d" height="%d" class="sparkline" preserveAspectRatio="none">`+
			`<polygon points="%s" fill="color-mix(in srgb, %s 12%%, transparent)"/>`+
			`<polyline points="%s" fill="none" stroke="%s" stroke-width="2" vector-effect="non-scaling-stroke"/>`+
			`</svg>`,
		width, height, width, height, area, stroke, polyline, stroke))
}

func gaugeSVG(value float64, label string, display string, tone string, size int) template.HTML {
	rad := float64(size) / 2.0
	cx, cy := rad, rad
	stroke := rad * 0.85
	r := rad * 0.7
	circ := 2 * math.Pi * r
	offset := circ * (1 - math.Min(1, math.Max(0, value/100)))
	return template.HTML(fmt.Sprintf(
		`<svg viewBox="0 0 %d %d" width="%d" height="%d" class="gauge">`+
			`<circle cx="%.1f" cy="%.1f" r="%.1f" fill="none" stroke="var(--line)" stroke-width="%.1f"/>`+
			`<circle cx="%.1f" cy="%.1f" r="%.1f" fill="none" stroke="var(--%s)" stroke-width="%.1f" stroke-dasharray="%.1f" stroke-dashoffset="%.1f" transform="rotate(-90 %.1f %.1f)"/>`+
			`<text x="%.1f" y="%.1f" text-anchor="middle" dominant-baseline="middle" class="gauge-value" fill="var(--fg)">%s</text>`+
			`<text x="%.1f" y="%.1f" text-anchor="middle" class="gauge-label" fill="var(--code)">%s</text>`+
			`</svg>`,
		size, size, size, size,
		cx, cy, r, stroke*0.14,
		cx, cy, r, tone, stroke*0.14, circ, offset, cx, cy,
		cx, cy, display,
		cx, cy+r*0.55, label))
}

func barMeter(label string, value, max float64, display string) template.HTML {
	if max <= 0 {
		max = 1
	}
	pct := math.Min(100, (value/max)*100)
	return template.HTML(fmt.Sprintf(
		`<div class="meter">`+
			`<div class="meter-head"><span class="meter-label">%s</span><span class="meter-value">%s</span></div>`+
			`<div class="meter-track"><div class="meter-bar" style="width:%.1f%%"></div></div>`+
			`</div>`,
		template.HTMLEscaper(label), template.HTMLEscaper(display), pct))
}

func toastHTML(kind, message string) string {
	return fmt.Sprintf(`<div class="toast toast-%s" role="status" data-kind="%s"><span class="toast-msg">%s</span></div>`,
		kind, kind, template.HTMLEscaper(message))
}

func jsonGet(m map[string]any, key string) any {
	if m == nil {
		return nil
	}
	return m[key]
}

func jsonString(v any) string {
	s, _ := v.(string)
	return s
}

func jsonNumber(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	}
	return 0
}

func dict(pairs ...any) map[string]any {
	m := make(map[string]any, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		if i+1 < len(pairs) {
			k, _ := pairs[i].(string)
			m[k] = pairs[i+1]
		}
	}
	return m
}

func sampleSeries(samples []map[string]any, key string) []float64 {
	out := make([]float64, 0, len(samples))
	for _, s := range samples {
		out = append(out, jsonNumber(s[key]))
	}
	return out
}

func sampleLast(samples []map[string]any, key string) float64 {
	if len(samples) == 0 {
		return 0
	}
	return jsonNumber(samples[len(samples)-1][key])
}

func setFlash(w http.ResponseWriter, r *http.Request, kind, message string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "rg_admin_flash",
		Value:    kind + "|" + message,
		Path:     "/",
		MaxAge:   30,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func getFlash(r *http.Request) (string, string) {
	c, err := r.Cookie("rg_admin_flash")
	if err != nil || c.Value == "" {
		return "", ""
	}
	parts := strings.SplitN(c.Value, "|", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}
