// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package access

import (
	"html"
	"net/http"
	"strings"
)

// WriteForm renders a minimal branded HTML form for password or pin entry.
// kind should be RulePassword or RulePIN. action is the form POST target.
func WriteForm(w http.ResponseWriter, brand, kind, action string) {
	if brand == "" {
		brand = "RavenGuard"
	}
	if action == "" {
		action = ""
	}
	label := "Password"
	inputType := "password"
	autocomplete := "current-password"
	name := "password"
	if kind == RulePIN {
		label = "PIN"
		inputType = "password"
		autocomplete = "one-time-code"
		name = "pin"
	}
	title := html.EscapeString(brand) + " Access"
	safeBrand := html.EscapeString(brand)
	safeLabel := html.EscapeString(label)
	safeAction := html.EscapeString(action)
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n")
	b.WriteString("<meta charset=\"utf-8\">\n")
	b.WriteString("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
	b.WriteString("<meta name=\"robots\" content=\"noindex,nofollow\">\n")
	b.WriteString("<title>")
	b.WriteString(title)
	b.WriteString("</title>\n<style>\n")
	b.WriteString(":root{--bg:#0f1419;--fg:#e7ecf1;--muted:#9aa7b5;--accent:#3d8bfd;--card:#1a222c;--border:#2a3542;}")
	b.WriteString("*{box-sizing:border-box;}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;")
	b.WriteString("font-family:ui-sans-serif,system-ui,sans-serif;background:radial-gradient(1200px 600px at 20% -10%,#1b2a3d,var(--bg));color:var(--fg);}")
	b.WriteString(".wrap{width:min(100%,22rem);padding:1.5rem;}")
	b.WriteString("h1{margin:0 0 .35rem;font-size:1.35rem;letter-spacing:.02em;}")
	b.WriteString("p{margin:0 0 1.25rem;color:var(--muted);font-size:.95rem;}")
	b.WriteString("form{background:var(--card);border:1px solid var(--border);padding:1.25rem;}")
	b.WriteString("label{display:block;font-size:.85rem;margin-bottom:.4rem;color:var(--muted);}")
	b.WriteString("input{width:100%;padding:.65rem .7rem;border:1px solid var(--border);background:#121820;color:var(--fg);font-size:1rem;}")
	b.WriteString("button{margin-top:1rem;width:100%;padding:.7rem;border:0;background:var(--accent);color:#fff;font-weight:600;cursor:pointer;}")
	b.WriteString("button:hover{filter:brightness(1.08);}")
	b.WriteString("</style>\n</head>\n<body>\n<div class=\"wrap\">\n")
	b.WriteString("<h1>")
	b.WriteString(safeBrand)
	b.WriteString("</h1>\n<p>Enter the ")
	b.WriteString(strings.ToLower(safeLabel))
	b.WriteString(" to continue.</p>\n")
	b.WriteString("<form method=\"post\" action=\"")
	b.WriteString(safeAction)
	b.WriteString("\">\n")
	b.WriteString("<label for=\"secret\">")
	b.WriteString(safeLabel)
	b.WriteString("</label>\n")
	b.WriteString("<input id=\"secret\" name=\"")
	b.WriteString(html.EscapeString(name))
	b.WriteString("\" type=\"")
	b.WriteString(inputType)
	b.WriteString("\" autocomplete=\"")
	b.WriteString(autocomplete)
	b.WriteString("\" required autofocus>\n")
	b.WriteString("<button type=\"submit\">Continue</button>\n")
	b.WriteString("</form>\n</div>\n</body>\n</html>\n")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(b.String()))
}

// WriteFormForPolicy picks password or pin from the policy rules and renders the form.
func (m *Manager) WriteFormForPolicy(w http.ResponseWriter, policyID, action string) {
	brand := m.Brand
	if brand == "" {
		brand = "RavenGuard"
	}
	kind := RulePassword
	if p, ok := m.Get(policyID); ok {
		for _, r := range p.Rules {
			if r.Type == RulePIN {
				kind = RulePIN
				break
			}
			if r.Type == RulePassword {
				kind = RulePassword
			}
		}
	}
	WriteForm(w, brand, kind, action)
}
