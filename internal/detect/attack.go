// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package detect

import (
	"net/http"
	"net/url"

	"github.com/Quad4-Software/ravenguard/internal/faststr"
)

var lowerBufPool = &lowerPool

// AttackMatch inspects path and query for common exploit probes.
// Returns a reason code when matched.
func AttackMatch(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	rawPath := r.URL.Path
	if r.URL.RawPath != "" {
		rawPath = r.URL.RawPath
	}
	rawQuery := r.URL.RawQuery
	if reason := scanAttackString(rawPath); reason != "" {
		return reason
	}
	if reason := scanAttackString(rawQuery); reason != "" {
		return reason
	}
	if indexByte(rawPath, '%') >= 0 {
		if dec, err := url.PathUnescape(rawPath); err == nil && dec != rawPath {
			if reason := scanAttackString(dec); reason != "" {
				return reason
			}
		}
	}
	if indexByte(rawQuery, '%') >= 0 {
		if dec, err := url.QueryUnescape(rawQuery); err == nil && dec != rawQuery {
			if reason := scanAttackString(dec); reason != "" {
				return reason
			}
		}
	}
	return ""
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func scanAttackString(s string) string {
	if s == "" {
		return ""
	}
	if containsByte(s, 0) || faststr.ContainsFold(s, "%00") {
		return "null_byte"
	}
	if faststr.ContainsFold(s, "../") || faststr.ContainsFold(s, `..\`) ||
		faststr.ContainsFold(s, "%2e%2e/") || faststr.ContainsFold(s, "%2e%2e%2f") ||
		faststr.ContainsFold(s, "..%2f") || faststr.ContainsFold(s, `%2e%2e\`) {
		return "path_traversal"
	}
	if faststr.ContainsFold(s, "/etc/passwd") || faststr.ContainsFold(s, `c:\windows`) {
		return "injection_probe"
	}
	if !mayHaveInjection(s) {
		return ""
	}

	bp := lowerBufPool.Get().(*[]byte)
	buf := faststr.AppendLowerASCII((*bp)[:0], s)
	for _, p := range attackSubs {
		if faststr.ContainsBytes(buf, p) {
			*bp = buf[:0]
			lowerBufPool.Put(bp)
			return "injection_probe"
		}
	}
	*bp = buf[:0]
	lowerBufPool.Put(bp)
	return ""
}

func mayHaveInjection(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '<', '\'', '"', '{', '$', '#', '\\', '+', '%', '(', ')', ';', '*', '`', ' ', ':', '_':
			return true
		}
	}
	return false
}

func containsByte(s string, c byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return true
		}
	}
	return false
}

var attackSubs = []string{
	"union select", "union%20select", "union+select",
	"' or '1'='1", "' or 1=1", "\" or \"1\"=\"1",
	"sleep(", "benchmark(", "waitfor delay",
	"<script", "%3cscript", "javascript:",
	"onerror=", "onload=",
	"/etc/passwd", "c:\\windows", "file://",
	"{{", "${jndi:", "#{",
	"xp_cmdshell", "information_schema",
	"into outfile", "load_file(",
}
