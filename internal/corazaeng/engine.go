// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package corazaeng

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/jcchavezs/mergefs"
	mergefsio "github.com/jcchavezs/mergefs/io"

	"github.com/Quad4-Software/ravenguard/internal/bodybuf"
	"github.com/Quad4-Software/ravenguard/internal/config"
)

// Result is the outcome of a Coraza evaluation.
type Result struct {
	Matched     bool
	ShouldBlock bool
	Status      int
	RuleID      int
	Data        string
	Action      string
	Error       string
}

// Engine wraps an optional Coraza WAF instance.
type Engine struct {
	mu      sync.RWMutex
	enabled bool
	mode    string
	waf     coraza.WAF
	skip    []string
	maxBody int64
}

// New builds an engine from config. When disabled, returns a no-op engine.
// Enabling Coraza the first time requires a process restart so rules load.
func New(cfg config.CorazaConfig) (*Engine, error) {
	e := &Engine{
		enabled: cfg.Enabled,
		mode:    strings.ToLower(strings.TrimSpace(cfg.Mode)),
		skip:    append([]string{}, cfg.SkipPathPrefixes...),
		maxBody: cfg.MaxBodyInspect,
	}
	if e.mode == "" {
		e.mode = "block"
	}
	if e.maxBody <= 0 {
		e.maxBody = 1 << 20
	}
	if !cfg.Enabled {
		return e, nil
	}
	waf, err := buildWAF(cfg)
	if err != nil {
		return nil, err
	}
	e.waf = waf
	return e, nil
}

func buildWAF(cfg config.CorazaConfig) (coraza.WAF, error) {
	paranoia := max(cfg.Paranoia, 1)
	if paranoia > 4 {
		paranoia = 4
	}
	maxBody := cfg.MaxBodyInspect
	if maxBody <= 0 {
		maxBody = 1 << 20
	}
	rulesDir, err := sanitizeRulesPath(cfg.RulesDir, true)
	if err != nil {
		return nil, err
	}
	rulesFile, err := sanitizeRulesPath(cfg.RulesFile, false)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	// Always On so interruptions surface. Mode controls ShouldBlock in Evaluate.
	fmt.Fprintf(&b, "SecRuleEngine On\n")
	fmt.Fprintf(&b, "SecRequestBodyAccess On\n")
	fmt.Fprintf(&b, "SecRequestBodyLimit %d\n", maxBody)
	if cfg.Directives != "" {
		b.WriteString(cfg.Directives)
		b.WriteByte('\n')
	}
	root := coraza.NewWAFConfig()
	if cfg.CRS {
		fmt.Fprintf(&b, "Include @coraza.conf-recommended\n")
		fmt.Fprintf(&b, "Include @crs-setup.conf.example\n")
		fmt.Fprintf(&b, "SecAction \"id:900001,phase:1,pass,nolog,t:none,setvar:tx.blocking_paranoia_level=%d\"\n", paranoia)
		fmt.Fprintf(&b, "SecAction \"id:900002,phase:1,pass,nolog,t:none,setvar:tx.detection_paranoia_level=%d\"\n", paranoia)
		fmt.Fprintf(&b, "Include @owasp_crs/*.conf\n")
		if rulesDir != "" {
			root = root.WithRootFS(mergefs.Merge(coreruleset.FS, mergefsio.OSFS))
			fmt.Fprintf(&b, "Include %s/*.conf\n", rulesDir)
		} else {
			root = root.WithRootFS(coreruleset.FS)
		}
	} else if rulesDir != "" {
		root = root.WithRootFS(mergefsio.OSFS)
		fmt.Fprintf(&b, "Include %s/*.conf\n", rulesDir)
	} else if strings.TrimSpace(cfg.Directives) == "" && rulesFile == "" {
		return nil, fmt.Errorf("coraza: enable crs or set rules_dir/directives")
	}
	if rulesFile != "" {
		if !cfg.CRS && rulesDir == "" {
			root = root.WithRootFS(mergefsio.OSFS)
		}
		fmt.Fprintf(&b, "Include %s\n", rulesFile)
	}
	return coraza.NewWAF(root.WithDirectives(b.String()))
}

// sanitizeRulesPath rejects path traversal and relative escapes for Include targets.
func sanitizeRulesPath(p string, dir bool) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", nil
	}
	if strings.Contains(p, "\n") || strings.Contains(p, "\r") || strings.Contains(p, `"`) {
		return "", fmt.Errorf("coraza: invalid rules path")
	}
	clean := filepath.Clean(p)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("coraza: rules path escapes working directory")
	}
	if dir {
		return strings.TrimRight(clean, string(filepath.Separator)), nil
	}
	return clean, nil
}

// Enabled reports whether evaluation is active.
func (e *Engine) Enabled() bool {
	if e == nil {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enabled && e.waf != nil
}

// Loaded reports whether rules are in memory (independent of enabled toggle).
func (e *Engine) Loaded() bool {
	if e == nil {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.waf != nil
}

// Mode returns block or detect.
func (e *Engine) Mode() string {
	if e == nil {
		return "block"
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.mode == "" {
		return "block"
	}
	return e.mode
}

// UpdateLive applies live-safe toggles. Enabling without loaded rules is a no-op for evaluation.
func (e *Engine) UpdateLive(enabled bool, mode string) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if enabled && e.waf == nil {
		e.enabled = false
	} else {
		e.enabled = enabled
	}
	if mode != "" {
		e.mode = strings.ToLower(strings.TrimSpace(mode))
	}
}

// Evaluate runs Coraza request phases against r. Body may be buffered and restored.
func (e *Engine) Evaluate(r *http.Request) Result {
	if !e.Enabled() || r == nil {
		return Result{}
	}
	e.mu.RLock()
	waf := e.waf
	skip := e.skip
	mode := e.mode
	maxBody := e.maxBody
	e.mu.RUnlock()
	if waf == nil {
		return Result{}
	}
	path := ""
	if r.URL != nil {
		path = r.URL.Path
	}
	for _, p := range skip {
		if pathSkipped(path, p) {
			return Result{}
		}
	}

	tx := waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()

	client, cport := splitRemote(r.RemoteAddr)
	tx.ProcessConnection(client, cport, "", 0)
	tx.ProcessURI(r.URL.String(), r.Method, r.Proto)
	for k, vr := range r.Header {
		for _, v := range vr {
			tx.AddRequestHeader(k, v)
		}
	}
	if r.Host != "" {
		tx.AddRequestHeader("Host", r.Host)
		tx.SetServerName(r.Host)
	}
	for _, te := range r.TransferEncoding {
		tx.AddRequestHeader("Transfer-Encoding", te)
	}

	if it := tx.ProcessRequestHeaders(); it != nil {
		return interruptResult(it, mode)
	}

	if !tx.IsRequestBodyAccessible() || r.Body == nil || r.Body == http.NoBody {
		return Result{}
	}

	buf, err := bodybuf.Capture(r, maxBody)
	if err != nil {
		return failClosed(mode, "body read failed")
	}
	if len(buf) == 0 {
		return Result{}
	}

	it, _, err := tx.ReadRequestBodyFrom(bytes.NewReader(buf))
	if err != nil {
		bodybuf.Restore(r, buf)
		return failClosed(mode, "coraza body buffer failed")
	}
	if it != nil {
		bodybuf.Restore(r, buf)
		return interruptResult(it, mode)
	}
	bodybuf.Restore(r, buf)

	it, err = tx.ProcessRequestBody()
	if err != nil {
		return failClosed(mode, "coraza body process failed")
	}
	if it != nil {
		return interruptResult(it, mode)
	}
	return Result{}
}

func pathSkipped(path, prefix string) bool {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return false
	}
	if path == prefix {
		return true
	}
	if strings.HasSuffix(prefix, "/") {
		return strings.HasPrefix(path, prefix)
	}
	return strings.HasPrefix(path, prefix+"/")
}

func failClosed(mode, msg string) Result {
	block := !strings.EqualFold(mode, "detect")
	return Result{
		Matched:     true,
		ShouldBlock: block,
		Status:      http.StatusForbidden,
		Action:      "deny",
		Data:        msg,
		Error:       msg,
	}
}

func interruptResult(it *types.Interruption, mode string) Result {
	return Result{
		Matched:     true,
		ShouldBlock: !strings.EqualFold(mode, "detect"),
		Status:      it.Status,
		RuleID:      it.RuleID,
		Data:        it.Data,
		Action:      it.Action,
	}
}

func splitRemote(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}
