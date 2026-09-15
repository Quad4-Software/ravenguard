// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Protocol selects the upstream HTTP version.
type Protocol string

const (
	ProtocolAuto  Protocol = "auto"
	ProtocolH2    Protocol = "h2"
	ProtocolH3    Protocol = "h3"
	ProtocolHTTP1 Protocol = "http1.1"
)

// Config builds a reverse proxy to a single upstream.
type Config struct {
	Target                *url.URL
	ConnectTimeout        time.Duration
	ResponseHeaderTimeout time.Duration
	IdleConnTimeout       time.Duration
	MaxIdleConns          int
	MaxIdleConnsPerHost   int
	MaxConnsPerHost       int
	FlushInterval         time.Duration
	SetHeaders            map[string]string
	StripPrefix           string
	ErrorHandler          func(http.ResponseWriter, *http.Request, error)
	// DialContext overrides the default TCP/unix dialer when set.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// Protocol chooses the upstream HTTP version.
	// "" or "h2" (default) uses HTTP/2, with an HTTP/1.1 fallback when AllowHTTP1 is true.
	// "h3" uses HTTP/3 (QUIC).
	// "auto" tries HTTP/3 first and falls back to HTTP/2/HTTP/1.1.
	// "http1.1" uses HTTP/1.1 only.
	Protocol string
	// TLSClientConfig is the TLS configuration for https and h3 upstreams.
	TLSClientConfig *tls.Config
	// AllowHTTP1 allows the HTTP/2 transport to fall back to HTTP/1.1.
	AllowHTTP1 bool
}

// Proxy is an httputil.ReverseProxy with lifecycle hooks.
type Proxy struct {
	*httputil.ReverseProxy
	closer idleCloser
}

type idleCloser interface {
	CloseIdleConnections()
}

// roundTripperCloser is an http.RoundTripper that can drain idle connections.
type roundTripperCloser interface {
	http.RoundTripper
	idleCloser
}

// CloseIdleConnections drains idle upstream connections.
func (p *Proxy) CloseIdleConnections() {
	if p == nil || p.closer == nil {
		return
	}
	p.closer.CloseIdleConnections()
}

// Close drains idle connections and releases protocol-specific resources
// (e.g. QUIC connections for HTTP/3).
func (p *Proxy) Close() error {
	if p == nil || p.closer == nil {
		return nil
	}
	p.closer.CloseIdleConnections()
	if c, ok := p.closer.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}

// New returns a reverse proxy for cfg.
func New(cfg Config) *Proxy {
	dial := DialFunc(cfg.Target, cfg.ConnectTimeout)
	if cfg.DialContext != nil {
		dial = cfg.DialContext
	}
	maxIdle := cfg.MaxIdleConns
	if maxIdle <= 0 {
		maxIdle = 256
	}
	perHost := cfg.MaxIdleConnsPerHost
	if perHost <= 0 {
		perHost = maxIdle
	}
	maxConns := cfg.MaxConnsPerHost
	if maxConns <= 0 {
		maxConns = 256
	}
	cfg.MaxIdleConns = maxIdle
	cfg.MaxIdleConnsPerHost = perHost
	cfg.MaxConnsPerHost = maxConns
	flush := cfg.FlushInterval
	if flush == 0 {
		flush = -1
	}

	proto := normalizeProtocol(cfg.Protocol)
	if cfg.DialContext != nil || IsUnix(cfg.Target) {
		// Custom dialers and Unix sockets cannot carry QUIC.
		if proto == ProtocolH3 {
			proto = ProtocolH2
		}
		if proto == ProtocolAuto {
			proto = ProtocolH2
		}
	}
	if proto == ProtocolAuto && IsH3Scheme(cfg.Target) {
		// An explicit h3:// target only speaks QUIC; TCP fallback is useless.
		proto = ProtocolH3
	}

	var rt roundTripperCloser
	switch proto {
	case ProtocolH3:
		rt = newH3Transport(cfg, dial, false)
	case ProtocolAuto:
		rt = newH3Transport(cfg, dial, true)
	default:
		rt = newTCPTransport(cfg, dial)
	}

	target := NormalizeTarget(cfg.Target)
	setHeaders := cfg.SetHeaders
	strip := strings.TrimSuffix(cfg.StripPrefix, "/")
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			out := pr.Out
			// Rewrite strips X-Forwarded-* from Out. Restore identity headers
			// the pipeline already set on the inbound request.
			if v := pr.In.Header.Get("X-Real-IP"); v != "" {
				out.Header.Set("X-Real-IP", v)
			}
			if v := pr.In.Header.Get("X-Forwarded-For"); v != "" {
				out.Header.Set("X-Forwarded-For", v)
			}
			if v := pr.In.Header.Get("X-Forwarded-Proto"); v != "" {
				out.Header.Set("X-Forwarded-Proto", v)
			}
			// Preserve the original host so multi-tenant origins can route by it.
			if host := pr.In.Host; host != "" {
				out.Header.Set("X-Forwarded-Host", host)
			}
			out.URL.Scheme = target.Scheme
			out.URL.Host = target.Host
			if IsUnix(cfg.Target) {
				out.URL.Scheme = "http"
				out.URL.Host = "localhost"
				out.Host = "localhost"
			} else {
				out.Host = target.Host
			}
			if proto == ProtocolH3 && out.URL.Scheme == "http" {
				// HTTP/3 runs over QUIC with TLS, so force https for the transport.
				out.URL.Scheme = "https"
			}
			if strip != "" {
				p := out.URL.Path
				if p == strip {
					out.URL.Path = "/"
				} else if strings.HasPrefix(p, strip+"/") {
					out.URL.Path = p[len(strip):]
					if out.URL.Path == "" {
						out.URL.Path = "/"
					}
				}
			}
			for k, v := range setHeaders {
				out.Header.Set(k, v)
			}
		},
		Transport:     rt,
		FlushInterval: flush,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if cfg.ErrorHandler != nil {
				cfg.ErrorHandler(w, r, err)
				return
			}
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
	return &Proxy{ReverseProxy: rp, closer: rt}
}

func normalizeProtocol(s string) Protocol {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "h3", "http3", "quic":
		return ProtocolH3
	case "http1.1", "http1", "http/1.1", "http/1", "h1":
		return ProtocolHTTP1
	case "auto":
		return ProtocolAuto
	default:
		return ProtocolH2
	}
}

func tlsClone(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return cfg.Clone()
}

func baseTransport(cfg Config, dial func(context.Context, string, string) (net.Conn, error)) *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           dial,
		TLSClientConfig:       cfg.TLSClientConfig,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: cfg.ResponseHeaderTimeout,
		IdleConnTimeout:       cfg.IdleConnTimeout,
		MaxIdleConns:          cfg.MaxIdleConns,
		MaxIdleConnsPerHost:   cfg.MaxIdleConnsPerHost,
		MaxConnsPerHost:       cfg.MaxConnsPerHost,
		DisableCompression:    true,
		WriteBufferSize:       32 << 10,
		ReadBufferSize:        32 << 10,
	}
}

func newTCPTransport(cfg Config, dial func(context.Context, string, string) (net.Conn, error)) roundTripperCloser {
	proto := normalizeProtocol(cfg.Protocol)
	if proto == ProtocolHTTP1 {
		t := baseTransport(cfg, dial)
		t.TLSClientConfig = tlsClone(cfg.TLSClientConfig)
		if t.TLSClientConfig.NextProtos == nil {
			t.TLSClientConfig.NextProtos = []string{"http/1.1"}
		}
		p := &http.Protocols{}
		p.SetHTTP1(true)
		t.Protocols = p
		return &closeTransport{t}
	}

	h1 := baseTransport(cfg, dial)
	h1.ForceAttemptHTTP2 = false
	h1.TLSClientConfig = tlsClone(cfg.TLSClientConfig)
	h1.TLSClientConfig.NextProtos = []string{"http/1.1"}
	h1p := &http.Protocols{}
	h1p.SetHTTP1(true)
	h1p.SetHTTP2(false)
	h1p.SetUnencryptedHTTP2(false)
	h1.Protocols = h1p

	h2 := baseTransport(cfg, dial)
	h2.TLSClientConfig = tlsClone(cfg.TLSClientConfig)
	h2p := &http.Protocols{}
	h2p.SetHTTP2(true)
	h2p.SetHTTP1(cfg.AllowHTTP1)
	if cfg.AllowHTTP1 {
		h2.TLSClientConfig.NextProtos = []string{"h2", "http/1.1"}
	} else {
		h2.TLSClientConfig.NextProtos = []string{"h2"}
		// Strict HTTP/2: cleartext origins get prior-knowledge h2c only.
		h2p.SetUnencryptedHTTP2(true)
	}
	h2.Protocols = h2p

	st := &switchingTransport{h2: h2, h1: h1}
	if cfg.AllowHTTP1 {
		// Cleartext origins get h2c when the peer speaks it and HTTP/1.1
		// otherwise. A dedicated transport is required because the standard
		// library only uses unencrypted HTTP/2 when HTTP/1 is disabled.
		h2c := baseTransport(cfg, dial)
		h2c.TLSClientConfig = tlsClone(cfg.TLSClientConfig)
		h2c.TLSClientConfig.NextProtos = []string{"h2"}
		h2cp := &http.Protocols{}
		h2cp.SetHTTP2(true)
		h2cp.SetUnencryptedHTTP2(true)
		h2c.Protocols = h2cp
		st.h2c = h2c
		st.prober = newH2CProber(dial, cfg.ConnectTimeout)
	}
	return st
}

type closeTransport struct {
	*http.Transport
}

func (c *closeTransport) CloseIdleConnections() {
	c.Transport.CloseIdleConnections()
}

func (c *closeTransport) Close() error {
	c.CloseIdleConnections()
	return nil
}

type switchingTransport struct {
	h2 *http.Transport
	h1 *http.Transport
	// h2c and prober are set only when allow_http1 is true: cleartext requests
	// use h2c when the origin speaks it and fall back to HTTP/1.1 otherwise.
	h2c    *http.Transport
	prober *h2cProber
}

func (s *switchingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if isWebSocket(req) {
		return s.h1.RoundTrip(req)
	}
	if s.h2c != nil && req.URL != nil && req.URL.Scheme == "http" {
		if !s.prober.useH2C(req.URL.Host) {
			return s.h1.RoundTrip(req)
		}
		att, retry := fallbackAttempt(req)
		resp, err := s.h2c.RoundTrip(att)
		if err == nil {
			return resp, nil
		}
		if att.Context().Err() == nil {
			s.prober.demote(req.URL.Host)
		}
		if r2, ok := retry(); ok {
			return s.h1.RoundTrip(r2)
		}
		return nil, err
	}
	return s.h2.RoundTrip(req)
}

func (s *switchingTransport) CloseIdleConnections() {
	s.h2.CloseIdleConnections()
	s.h1.CloseIdleConnections()
	if s.h2c != nil {
		s.h2c.CloseIdleConnections()
	}
}

func (s *switchingTransport) Close() error {
	s.CloseIdleConnections()
	return nil
}

func isWebSocket(req *http.Request) bool {
	return req != nil && req.Method == http.MethodGet && strings.EqualFold(req.Header.Get("Upgrade"), "websocket")
}

// h2cProber tracks which cleartext origins speak HTTP/2. Results are cached:
// capable hosts are re-checked after an hour, incapable after five minutes.
type h2cProber struct {
	dial    func(context.Context, string, string) (net.Conn, error)
	timeout time.Duration
	mu      sync.Mutex
	cache   map[string]h2cProbeEntry
	pending map[string]bool
}

type h2cProbeEntry struct {
	h2c     bool
	expires time.Time
}

func newH2CProber(dial func(context.Context, string, string) (net.Conn, error), timeout time.Duration) *h2cProber {
	if timeout <= 0 || timeout > 3*time.Second {
		timeout = 3 * time.Second
	}
	return &h2cProber{
		dial:    dial,
		timeout: timeout,
		cache:   make(map[string]h2cProbeEntry),
		pending: make(map[string]bool),
	}
}

// useH2C reports whether addr is known to speak h2c. Requests made while a
// probe is in flight use HTTP/1.1.
func (p *h2cProber) useH2C(addr string) bool {
	p.mu.Lock()
	e, ok := p.cache[addr]
	if ok && time.Now().Before(e.expires) {
		p.mu.Unlock()
		return e.h2c
	}
	if p.pending[addr] {
		p.mu.Unlock()
		return false
	}
	p.pending[addr] = true
	p.mu.Unlock()

	go func() {
		ok := probeH2C(p.dial, addr, p.timeout)
		ttl := 5 * time.Minute
		if ok {
			ttl = time.Hour
		}
		p.mu.Lock()
		p.cache[addr] = h2cProbeEntry{h2c: ok, expires: time.Now().Add(ttl)}
		delete(p.pending, addr)
		p.mu.Unlock()
	}()
	return false
}

// demote marks addr as not h2c-capable after a failed h2c exchange so later
// requests skip h2c until the entry expires.
func (p *h2cProber) demote(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cache[addr] = h2cProbeEntry{h2c: false, expires: time.Now().Add(5 * time.Minute)}
}

var h2cPreface = append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
	// Empty SETTINGS frame.
	0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00)

// probeH2C reports whether addr answers the HTTP/2 client preface with a
// server SETTINGS frame on stream 0.
func probeH2C(dial func(context.Context, string, string) (net.Conn, error), addr string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err = conn.Write(h2cPreface); err != nil {
		return false
	}
	var hdr [9]byte
	if _, err = io.ReadFull(conn, hdr[:]); err != nil {
		return false
	}
	if bytes.HasPrefix(hdr[:], []byte("HTTP/")) {
		return false
	}
	streamID := binary.BigEndian.Uint32(hdr[5:9]) & 0x7fffffff
	return hdr[3] == 0x04 && streamID == 0
}

type countingBody struct {
	rc io.ReadCloser
	n  int64
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countingBody) Close() error { return c.rc.Close() }

// fallbackAttempt prepares req for a speculative transport attempt and returns
// a retry func producing a request that is safe to send on a different
// transport: the original request when the body is untouched, a clone with a
// fresh GetBody, or false when the failed attempt consumed part of the body.
func fallbackAttempt(req *http.Request) (attempt *http.Request, retry func() (*http.Request, bool)) {
	if req.Body == nil || req.Body == http.NoBody {
		return req, func() (*http.Request, bool) { return req, true }
	}
	if req.GetBody != nil {
		if b, err := req.GetBody(); err == nil {
			att := req.Clone(req.Context())
			att.Body = b
			return att, func() (*http.Request, bool) {
				b2, err := req.GetBody()
				if err != nil {
					return nil, false
				}
				r2 := req.Clone(req.Context())
				r2.Body = b2
				return r2, true
			}
		}
	}
	cb := &countingBody{rc: req.Body}
	att := req.Clone(req.Context())
	att.Body = cb
	return att, func() (*http.Request, bool) {
		if cb.n != 0 {
			return nil, false
		}
		r2 := req.Clone(req.Context())
		r2.Body = req.Body
		return r2, true
	}
}

func newH3Transport(cfg Config, dial func(context.Context, string, string) (net.Conn, error), fallback bool) roundTripperCloser {
	tlsCfg := cfg.TLSClientConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	}
	h3t := &http3.Transport{
		TLSClientConfig:    tlsClone(tlsCfg),
		DisableCompression: true,
	}
	if !fallback {
		return &h3OnlyTransport{h3: h3t}
	}
	return &h3AutoTransport{
		h3:       h3t,
		fallback: newTCPTransport(cfg, dial),
		tlsCfg:   tlsCfg,
		timeout:  3 * time.Second,
		cache:    make(map[string]protoCacheEntry),
		pending:  make(map[string]bool),
	}
}

type h3OnlyTransport struct {
	h3 *http3.Transport
}

func (h *h3OnlyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return h.h3.RoundTrip(req)
}

func (h *h3OnlyTransport) CloseIdleConnections() {
	h.h3.CloseIdleConnections()
}

func (h *h3OnlyTransport) Close() error {
	return h.h3.Close()
}

type h3AutoTransport struct {
	h3       *http3.Transport
	fallback roundTripperCloser
	tlsCfg   *tls.Config
	timeout  time.Duration
	mu       sync.Mutex
	cache    map[string]protoCacheEntry
	pending  map[string]bool
}

type protoCacheEntry struct {
	proto   string
	expires time.Time
}

func (a *h3AutoTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil || req.URL.Scheme != "https" {
		// HTTP/3 always runs over TLS; cleartext targets go straight to TCP.
		return a.fallback.RoundTrip(req)
	}
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}

	switch a.cached(host) {
	case "h3":
		att, retry := fallbackAttempt(req)
		resp, err := a.h3.RoundTrip(att)
		if err == nil {
			return resp, nil
		}
		if att.Context().Err() == nil {
			a.setCache(host, "h2", time.Now().Add(5*time.Minute))
		}
		if r2, ok := retry(); ok {
			return a.fallback.RoundTrip(r2)
		}
		return nil, err
	case "h2":
		return a.fallback.RoundTrip(req)
	}

	// Unknown capability: serve this request over TCP now and probe QUIC in
	// the background so the first request is not stalled by a handshake.
	a.probeAsync(host)
	return a.fallback.RoundTrip(req)
}

func (a *h3AutoTransport) cached(host string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	e, ok := a.cache[host]
	if ok && time.Now().Before(e.expires) {
		return e.proto
	}
	return ""
}

func (a *h3AutoTransport) setCache(host, proto string, expires time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cache[host] = protoCacheEntry{proto: proto, expires: expires}
}

func (a *h3AutoTransport) probeAsync(host string) {
	a.mu.Lock()
	if a.pending[host] {
		a.mu.Unlock()
		return
	}
	a.pending[host] = true
	a.mu.Unlock()
	go func() {
		proto, ttl := "h2", 5*time.Minute
		if probeQUIC(a.tlsCfg, host, a.timeout) {
			proto, ttl = "h3", time.Hour
		}
		a.setCache(host, proto, time.Now().Add(ttl))
		a.mu.Lock()
		delete(a.pending, host)
		a.mu.Unlock()
	}()
}

// probeQUIC reports whether hostport completes a QUIC handshake within timeout.
func probeQUIC(base *tls.Config, hostport string, timeout time.Duration) bool {
	tlsCfg := tlsClone(base)
	tlsCfg.NextProtos = []string{http3.NextProtoH3}
	addr := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		if tlsCfg.ServerName == "" {
			tlsCfg.ServerName = h
		}
	} else {
		if tlsCfg.ServerName == "" {
			tlsCfg.ServerName = hostport
		}
		addr = net.JoinHostPort(hostport, "443")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := quic.DialAddrEarly(ctx, addr, tlsCfg, nil)
	if err != nil {
		return false
	}
	_ = conn.CloseWithError(0, "")
	return true
}

func (a *h3AutoTransport) CloseIdleConnections() {
	a.h3.CloseIdleConnections()
	a.fallback.CloseIdleConnections()
}

func (a *h3AutoTransport) Close() error {
	_ = a.h3.Close()
	if c, ok := a.fallback.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}

func IsUnix(u *url.URL) bool {
	if u == nil {
		return false
	}
	return u.Scheme == "unix" || strings.HasPrefix(u.Path, "/") && u.Host == "" && u.Scheme == ""
}

// IsH3Scheme reports whether u names an HTTP/3 (QUIC) target.
func IsH3Scheme(u *url.URL) bool {
	if u == nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "h3", "http3", "quic":
		return true
	}
	return false
}

func UnixPath(u *url.URL) string {
	if u == nil {
		return ""
	}
	if u.Scheme == "unix" {
		if u.Path != "" {
			return u.Path
		}
		return u.Opaque
	}
	return u.Path
}

func DialFunc(target *url.URL, timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}
	if target != nil && target.Scheme == "unix" {
		path := UnixPath(target)
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "unix", path)
		}
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := d.DialContext(ctx, network, addr)
		if err != nil && isLandlockBlocked(err) {
			_, port, _ := net.SplitHostPort(addr)
			slog.Warn("landlock blocked connect", "addr", addr, "port", port,
				"hint", "add the port to [sandbox.landlock] connect_tcp or set restrict_net=false")
		}
		return conn, err
	}
}

func isLandlockBlocked(err error) bool {
	return errors.Is(err, os.ErrPermission) || strings.Contains(err.Error(), "connect: permission denied")
}

func NormalizeTarget(u *url.URL) *url.URL {
	if u == nil {
		return &url.URL{Scheme: "http", Host: "127.0.0.1"}
	}
	out := *u
	switch strings.ToLower(out.Scheme) {
	case "unix":
		out.Scheme = "http"
		out.Host = "localhost"
		out.Path = ""
		out.Opaque = ""
	case "ws":
		out.Scheme = "http"
	case "wss":
		out.Scheme = "https"
	case "h3", "http3", "quic":
		out.Scheme = "https"
	}
	return &out
}

func ParseSetHeaders(list []string) map[string]string {
	out := make(map[string]string, len(list))
	for _, s := range list {
		k, v, ok := strings.Cut(s, ":")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

func ParseUpstreamURL(raw string) (*url.URL, error) {
	if after, ok := strings.CutPrefix(raw, "unix://"); ok {
		path := after
		return &url.URL{Scheme: "unix", Path: path}, nil
	}
	if after, ok := strings.CutPrefix(raw, "unix:"); ok {
		path := after
		return &url.URL{Scheme: "unix", Path: path}, nil
	}
	if after, ok := strings.CutPrefix(raw, "h3://"); ok {
		return &url.URL{Scheme: "h3", Host: after}, nil
	}
	return url.Parse(raw)
}

type errString string

func (e errString) Error() string { return string(e) }

// BuildTLSClientConfig creates a TLS config from file paths.
func BuildTLSClientConfig(caFile, clientCertFile, clientKeyFile string, insecureSkipVerify bool) (*tls.Config, error) {
	cfg := &tls.Config{}
	if insecureSkipVerify {
		cfg.InsecureSkipVerify = true
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("upstream ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("upstream ca_file: no valid certificates")
		}
		cfg.RootCAs = pool
	}
	if clientCertFile != "" && clientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("upstream client cert: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}
