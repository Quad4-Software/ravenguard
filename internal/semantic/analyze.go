// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package semantic

import (
	"bytes"
	"strings"
)

func scoreSQLi(b []byte) Result {
	low := bytes.ToLower(b)
	score := 0
	conf := 0.0
	var hit string

	if hasSQLUnionSelect(low) {
		score += 85
		conf = 0.92
		hit = "union_select"
	}
	if bytes.Contains(low, []byte("information_schema")) || bytes.Contains(low, []byte("load_file(")) {
		score += 40
		conf = maxf(conf, 0.9)
		hit = "schema_probe"
	}
	if hasStackedQuery(low) {
		score += 35
		conf = maxf(conf, 0.85)
		hit = "stacked"
	}
	if hasTautology(low) {
		score += 45
		conf = maxf(conf, 0.88)
		hit = "tautology"
	}
	if bytes.Contains(low, []byte("sleep(")) || bytes.Contains(low, []byte("benchmark(")) || bytes.Contains(low, []byte("waitfor delay")) {
		score += 50
		conf = maxf(conf, 0.9)
		hit = "time_based"
	}
	if bytes.Contains(low, []byte("drop table")) || bytes.Contains(low, []byte("drop database")) {
		score += 60
		conf = maxf(conf, 0.9)
		hit = "drop"
	}
	if score > 100 {
		score = 100
	}
	if score == 0 {
		return Result{}
	}
	return Result{Family: "sqli", Score: score, Confidence: conf, Evidence: TruncEvidence(b, 128) + ":" + hit}
}

func hasSQLUnionSelect(low []byte) bool {
	idx := bytes.Index(low, []byte("union"))
	for idx >= 0 {
		rest := low[idx+5:]
		j := 0
		for j < len(rest) && (rest[j] == ' ' || rest[j] == '\t' || rest[j] == '\n' || rest[j] == '\r' || rest[j] == '/' || rest[j] == '*') {
			// skip spaces and simple comment openers carefully
			if rest[j] == '/' && j+1 < len(rest) && rest[j+1] == '*' {
				end := bytes.Index(rest[j+2:], []byte("*/"))
				if end < 0 {
					break
				}
				j += end + 4
				continue
			}
			if rest[j] == '/' || rest[j] == '*' {
				break
			}
			j++
		}
		if j < len(rest) && bytes.HasPrefix(rest[j:], []byte("select")) {
			return true
		}
		next := bytes.Index(low[idx+5:], []byte("union"))
		if next < 0 {
			return false
		}
		idx = idx + 5 + next
	}
	return false
}

func hasStackedQuery(low []byte) bool {
	// semicolon followed by sql verb
	for i := range low {
		if low[i] != ';' {
			continue
		}
		j := i + 1
		for j < len(low) && (low[j] == ' ' || low[j] == '\t') {
			j++
		}
		rest := low[j:]
		for _, v := range []string{"select", "insert", "update", "delete", "drop", "alter", "create", "exec", "declare"} {
			if bytes.HasPrefix(rest, []byte(v)) {
				return true
			}
		}
	}
	return false
}

func hasTautology(low []byte) bool {
	patterns := []string{
		"' or '1'='1",
		"' or 1=1",
		"\" or \"1\"=\"1",
		" or 1=1--",
		"' or ''='",
		"1' or '1'='1",
	}
	s := string(low)
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	// ' OR <digit>=<digit>
	if bytes.Contains(low, []byte("' or ")) || bytes.Contains(low, []byte("'||")) {
		if bytes.Contains(low, []byte("=")) {
			return true
		}
	}
	return false
}

func scoreXSS(b []byte) Result {
	low := bytes.ToLower(b)
	score := 0
	conf := 0.0
	hit := ""
	if bytes.Contains(low, []byte("<script")) || bytes.Contains(low, []byte("</script")) {
		score += 80
		conf = 0.95
		hit = "script_tag"
	}
	if bytes.Contains(low, []byte("javascript:")) {
		score += 70
		conf = maxf(conf, 0.9)
		hit = "js_uri"
	}
	if bytes.Contains(low, []byte("onerror=")) || bytes.Contains(low, []byte("onload=")) || bytes.Contains(low, []byte("onclick=")) {
		score += 65
		conf = maxf(conf, 0.88)
		hit = "event_handler"
	}
	if bytes.Contains(low, []byte("<svg")) && bytes.Contains(low, []byte("onload")) {
		score += 70
		conf = maxf(conf, 0.9)
		hit = "svg_onload"
	}
	if bytes.Contains(low, []byte("document.cookie")) || bytes.Contains(low, []byte("document.write")) {
		score += 40
		conf = maxf(conf, 0.8)
		if hit == "" {
			hit = "dom_sink"
		}
	}
	if score > 100 {
		score = 100
	}
	if score == 0 {
		return Result{}
	}
	return Result{Family: "xss", Score: score, Confidence: conf, Evidence: TruncEvidence(b, 128) + ":" + hit}
}

func scoreCMD(b []byte) Result {
	low := bytes.ToLower(b)
	score := 0
	conf := 0.0
	hit := ""
	if bytes.ContainsAny(b, "|&;`") && hasShellVerb(low) {
		score += 75
		conf = 0.9
		hit = "shell_meta"
	}
	if bytes.Contains(low, []byte("$(")) || bytes.Contains(low, []byte("`")) {
		if hasShellVerb(low) {
			score += 70
			conf = maxf(conf, 0.88)
			hit = "subst"
		}
	}
	if bytes.Contains(low, []byte("/bin/sh")) || bytes.Contains(low, []byte("/bin/bash")) || bytes.Contains(low, []byte("cmd.exe")) {
		score += 80
		conf = maxf(conf, 0.92)
		hit = "shell_path"
	}
	if score > 100 {
		score = 100
	}
	if score == 0 {
		return Result{}
	}
	return Result{Family: "cmd", Score: score, Confidence: conf, Evidence: TruncEvidence(b, 128) + ":" + hit}
}

func hasShellVerb(low []byte) bool {
	verbs := [][]byte{
		[]byte("cat "), []byte("cat/"), []byte("cat+"),
		[]byte("wget "), []byte("curl "), []byte("nc "),
		[]byte("bash "), []byte("sh "), []byte("powershell"),
		[]byte("python "), []byte("perl "), []byte("chmod "), []byte("chown "),
		[]byte("/etc/passwd"), []byte("cmd.exe"),
	}
	for _, v := range verbs {
		if bytes.Contains(low, v) {
			return true
		}
	}
	return false
}

func scorePath(b []byte) Result {
	score := 0
	conf := 0.0
	hit := ""
	if bytes.Contains(b, []byte("../")) || bytes.Contains(b, []byte("..\\")) {
		score += 55
		conf = 0.85
		hit = "dotdot"
	}
	if bytes.Contains(b, []byte("%2e%2e")) || bytes.Contains(bytes.ToLower(b), []byte("%2e%2e%2f")) {
		score += 70
		conf = maxf(conf, 0.9)
		hit = "encoded_dotdot"
	}
	low := bytes.ToLower(b)
	if bytes.Contains(low, []byte("/etc/passwd")) || bytes.Contains(low, []byte("windows\\system32")) || bytes.Contains(low, []byte("boot.ini")) {
		score += 80
		conf = maxf(conf, 0.93)
		hit = "sensitive_file"
	}
	if bytes.Contains(b, []byte{0}) {
		score += 60
		conf = maxf(conf, 0.9)
		hit = "null_byte"
	}
	if score > 100 {
		score = 100
	}
	if score == 0 {
		return Result{}
	}
	return Result{Family: "path", Score: score, Confidence: conf, Evidence: TruncEvidence(b, 128) + ":" + hit}
}

func maxf(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
