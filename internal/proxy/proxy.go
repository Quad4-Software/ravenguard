// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

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
		// Tunnels and Unix sockets cannot carry QUIC.
		if proto == ProtocolH3 {
			proto = ProtocolH2
		}
		if proto == ProtocolAuto {
			proto = ProtocolH2
		}
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

	h2 := baseTransport(cfg, dial)
	h2.TLSClientConfig = tlsClone(cfg.TLSClientConfig)
	h2p := &http.Protocols{}
	h2p.SetHTTP2(true)
	h2p.SetUnencryptedHTTP2(true)
	h2p.SetHTTP1(cfg.AllowHTTP1)
	if cfg.AllowHTTP1 {
		h2.TLSClientConfig.NextProtos = []string{"h2", "http/1.1"}
	} else {
		h2.TLSClientConfig.NextProtos = []string{"h2"}
	}
	h2.Protocols = h2p

	h1 := baseTransport(cfg, dial)
	h1.ForceAttemptHTTP2 = false
	h1.TLSClientConfig = tlsClone(cfg.TLSClientConfig)
	h1.TLSClientConfig.NextProtos = []string{"http/1.1"}
	h1p := &http.Protocols{}
	h1p.SetHTTP1(true)
	h1p.SetHTTP2(false)
	h1p.SetUnencryptedHTTP2(false)
	h1.Protocols = h1p

	return &switchingTransport{h2: h2, h1: h1}
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
}

func (s *switchingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if isWebSocket(req) {
		return s.h1.RoundTrip(req)
	}
	return s.h2.RoundTrip(req)
}

func (s *switchingTransport) CloseIdleConnections() {
	s.h2.CloseIdleConnections()
	s.h1.CloseIdleConnections()
}

func (s *switchingTransport) Close() error {
	s.CloseIdleConnections()
	return nil
}

func isWebSocket(req *http.Request) bool {
	return req != nil && req.Method == http.MethodGet && strings.EqualFold(req.Header.Get("Upgrade"), "websocket")
}

func newH3Transport(cfg Config, dial func(context.Context, string, string) (net.Conn, error), fallback bool) roundTripperCloser {
	tlsCfg := cfg.TLSClientConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	}
	h3t := &http3.Transport{
		TLSClientConfig:    tlsCfg,
		DisableCompression: true,
	}
	if !fallback {
		return &h3OnlyTransport{h3: h3t}
	}
	return &h3AutoTransport{
		h3:       h3t,
		fallback: newTCPTransport(cfg, dial),
		timeout:  5 * time.Second,
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
	timeout  time.Duration
	mu       sync.RWMutex
	cache    map[string]protoCacheEntry
}

type protoCacheEntry struct {
	proto   string
	expires time.Time
}

func (a *h3AutoTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}

	a.mu.RLock()
	e, ok := a.cache[host]
	a.mu.RUnlock()
	now := time.Now()
	if ok && now.Before(e.expires) {
		if e.proto == "h3" {
			return a.h3.RoundTrip(req)
		}
		return a.fallback.RoundTrip(req)
	}

	// Try HTTP/3 with a bounded probe. If the upstream does not speak QUIC
	// this will fail quickly and we fall back to HTTP/2/1.1.
	ctx, cancel := context.WithTimeout(req.Context(), a.timeout)
	defer cancel()
	h3Req := req.Clone(ctx)
	resp, err := a.h3.RoundTrip(h3Req)
	if err == nil {
		a.setCache(host, "h3", now.Add(1*time.Hour))
		return resp, nil
	}
	a.setCache(host, "h2", now.Add(5*time.Minute))
	return a.fallback.RoundTrip(req)
}

func (a *h3AutoTransport) setCache(host, proto string, expires time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cache == nil {
		a.cache = make(map[string]protoCacheEntry)
	}
	a.cache[host] = protoCacheEntry{proto: proto, expires: expires}
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
	case "tunnel":
		out.Scheme = "http"
		out.Host = "tunnel.local"
		out.Path = ""
		out.Opaque = ""
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
	if after, ok := strings.CutPrefix(raw, "tunnel://"); ok {
		after = strings.TrimSpace(after)
		connectorID, upstreamID, cutOK := strings.Cut(after, "/")
		if !cutOK || connectorID == "" || upstreamID == "" {
			return nil, &url.Error{Op: "parse", URL: raw, Err: errBadTunnelURL}
		}
		return &url.URL{Scheme: "tunnel", Host: connectorID, Path: "/" + upstreamID}, nil
	}
	if after, ok := strings.CutPrefix(raw, "h3://"); ok {
		return &url.URL{Scheme: "h3", Host: after}, nil
	}
	return url.Parse(raw)
}

var errBadTunnelURL = errString("tunnel:// requires connector_id/upstream_id")

type errString string

func (e errString) Error() string { return string(e) }

// TunnelParts extracts connector and upstream ids from a tunnel:// URL.
func TunnelParts(u *url.URL) (connectorID, upstreamID string, ok bool) {
	if u == nil || !strings.EqualFold(u.Scheme, "tunnel") {
		return "", "", false
	}
	connectorID = u.Host
	upstreamID = strings.TrimPrefix(u.Path, "/")
	if connectorID == "" || upstreamID == "" {
		return "", "", false
	}
	return connectorID, upstreamID, true
}

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
