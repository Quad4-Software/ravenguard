// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package proxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

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
}

type Proxy struct {
	*httputil.ReverseProxy
	transport *http.Transport
}

// CloseIdleConnections drains idle upstream connections.
func (p *Proxy) CloseIdleConnections() {
	if p == nil || p.transport == nil {
		return
	}
	p.transport.CloseIdleConnections()
}

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
	maxConns := max(cfg.MaxConnsPerHost, 0)
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dial,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          maxIdle,
		MaxIdleConnsPerHost:   perHost,
		MaxConnsPerHost:       maxConns,
		IdleConnTimeout:       cfg.IdleConnTimeout,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: cfg.ResponseHeaderTimeout,
		DisableCompression:    true,
		WriteBufferSize:       32 << 10,
		ReadBufferSize:        32 << 10,
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
			out.URL.Scheme = target.Scheme
			out.URL.Host = target.Host
			if IsUnix(cfg.Target) {
				out.URL.Scheme = "http"
				out.URL.Host = "localhost"
				out.Host = "localhost"
			} else {
				out.Host = target.Host
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
		Transport:     transport,
		FlushInterval: cfg.FlushInterval,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if cfg.ErrorHandler != nil {
				cfg.ErrorHandler(w, r, err)
				return
			}
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
	return &Proxy{ReverseProxy: rp, transport: transport}
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
	return d.DialContext
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
