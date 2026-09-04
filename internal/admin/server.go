// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package admin

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/admin/api"
	"github.com/Quad4-Software/ravenguard/internal/admin/auth"
	"github.com/Quad4-Software/ravenguard/internal/admin/ops"
	"github.com/Quad4-Software/ravenguard/internal/admin/store"
	"github.com/Quad4-Software/ravenguard/internal/admin/ui"
	"github.com/Quad4-Software/ravenguard/internal/agentprotocol"
	"github.com/Quad4-Software/ravenguard/internal/config"
)

type Server struct {
	cfg     config.AdminConfig
	tlsCfg  *tls.Config
	handler http.Handler
	store   *store.Store
}

type Options struct {
	Config               config.AdminConfig
	TLSCertFile          string
	TLSKeyFile           string
	Runtime              *ops.Runtime
	SecureCookie         bool
	ReloadRoutes         func() error
	CertStatus           func() any
	CertRenew            func(ctx context.Context, host string) error
	LogSnapshot          func(limit int, level string) any
	RequestByRay         func(ray string) (any, bool)
	RequestsRecent       func(limit int) any
	ManualCertPut        func(hostname, certPEM, keyPEM string) error
	ManualCertDelete     func(hostname string) error
	CertDetail           func(hostname string) (any, error)
	ACMEManage           func(ctx context.Context, hosts []string) error
	BootstrapUpstreamURL string
	AgentRegistry        *agentprotocol.Registry
	HubKeys              *agentprotocol.KeyPair
	HubPublicURL         string
	LocalTarget          ops.ProxyTarget
	MountAgentConnect    bool
}

func New(opts Options) (*Server, error) {
	st, err := store.Open(opts.Config.DataDir)
	if err != nil {
		return nil, err
	}
	n, err := st.CountUsers()
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	if n == 0 {
		user := strings.TrimSpace(opts.Config.BootstrapUser)
		if user == "" {
			user = "admin"
		}
		pass := opts.Config.BootstrapPassword
		generated := false
		if pass == "" {
			var gerr error
			pass, gerr = auth.RandomPassword(18)
			if gerr != nil {
				_ = st.Close()
				return nil, fmt.Errorf("generate bootstrap password: %w", gerr)
			}
			generated = true
		}
		hash, err := auth.HashPassword(pass)
		if err != nil {
			_ = st.Close()
			return nil, fmt.Errorf("bootstrap password: %w", err)
		}
		if _, err := st.BootstrapOwner(user, hash); err != nil {
			_ = st.Close()
			return nil, err
		}
		passFile := filepath.Join(opts.Config.DataDir, "initial_admin_password")
		if err := os.WriteFile(passFile, []byte(pass+"\n"), 0o600); err != nil {
			slog.Warn("admin bootstrap could not write password file", "path", passFile, "err", err)
		}
		if generated {
			slog.Warn("admin initial owner created (change this password after login)",
				"user", user,
				"password", pass,
				"password_file", passFile,
			)
		} else {
			slog.Info("admin bootstrap owner created", "user", user, "password_file", passFile)
		}
	}

	if payload, err := st.GetConfigOverrides(); err == nil && payload != "" && payload != "{}" {
		if safe, err := ops.DecodeSafeConfig(payload); err == nil {
			_ = opts.Runtime.ApplySafeConfig(safe)
			if safe.QFeeds != nil {
				_ = opts.Runtime.ApplyQFeeds(*safe.QFeeds)
			}
		}
	}

	if opts.BootstrapUpstreamURL != "" {
		if err := st.BootstrapDefaultUpstream("default", opts.BootstrapUpstreamURL); err != nil {
			_ = st.Close()
			return nil, fmt.Errorf("bootstrap upstream: %w", err)
		}
	}

	if opts.Runtime != nil {
		if opts.ReloadRoutes != nil {
			opts.Runtime.ReloadRoutes = opts.ReloadRoutes
		}
		if opts.CertStatus != nil {
			opts.Runtime.CertStatus = opts.CertStatus
		}
		if opts.CertRenew != nil {
			opts.Runtime.CertRenew = opts.CertRenew
		}
		if opts.LogSnapshot != nil {
			opts.Runtime.LogSnapshot = opts.LogSnapshot
		}
		if opts.RequestByRay != nil {
			opts.Runtime.RequestByRay = opts.RequestByRay
		}
		if opts.RequestsRecent != nil {
			opts.Runtime.RequestsRecent = opts.RequestsRecent
		}
		if opts.ManualCertPut != nil {
			opts.Runtime.ManualCertPut = opts.ManualCertPut
		}
		if opts.ManualCertDelete != nil {
			opts.Runtime.ManualCertDelete = opts.ManualCertDelete
		}
		if opts.CertDetail != nil {
			opts.Runtime.CertDetail = opts.CertDetail
		}
		if opts.ACMEManage != nil {
			opts.Runtime.ACMEManage = opts.ACMEManage
		}
	}

	apiSrv := &api.Server{
		Store:            st,
		Runtime:          opts.Runtime,
		Admin:            opts.Config,
		Lockout:          auth.NewLockout(),
		SecureCookie:     opts.SecureCookie,
		ReloadRoutes:     opts.ReloadRoutes,
		CertStatus:       opts.CertStatus,
		CertRenew:        opts.CertRenew,
		LogSnapshot:      opts.LogSnapshot,
		RequestByRay:     opts.RequestByRay,
		RequestsRecent:   opts.RequestsRecent,
		ManualCertPut:    opts.ManualCertPut,
		ManualCertDelete: opts.ManualCertDelete,
		CertDetail:       opts.CertDetail,
		ACMEManage:       opts.ACMEManage,
		AgentRegistry:    opts.AgentRegistry,
		HubKeys:          opts.HubKeys,
		HubPublicURL:     opts.HubPublicURL,
		LocalTarget:      opts.LocalTarget,
	}

	mux := http.NewServeMux()
	apiSrv.Mount(mux, opts.Config.BasePath)
	if opts.MountAgentConnect && opts.AgentRegistry != nil && opts.HubKeys != nil {
		hub := &agentprotocol.Hub{
			Keys:     *opts.HubKeys,
			Lookup:   st,
			Registry: opts.AgentRegistry,
			OnReady: func(ctx context.Context, sess *agentprotocol.Session) {
				state, err := st.DesiredState(sess.ProxyID)
				if err != nil || state.Revision == 0 {
					return
				}
				_, _ = sess.Call(ctx, agentprotocol.OpDesiredApply, state)
			},
		}
		p := strings.TrimSuffix(opts.Config.BasePath, "/")
		mux.HandleFunc(p+agentprotocol.ConnectPath, hub.HandleConnect)
	}
	mux.Handle("/", ui.Handler(opts.Config.BasePath))

	var tlsCfg *tls.Config
	if opts.Config.HTTPS != "" {
		certFile := opts.Config.CertFile
		keyFile := opts.Config.KeyFile
		if certFile == "" {
			certFile = opts.TLSCertFile
		}
		if keyFile == "" {
			keyFile = opts.TLSKeyFile
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			_ = st.Close()
			return nil, fmt.Errorf("admin tls: %w", err)
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}

	return &Server{
		cfg:     opts.Config,
		tlsCfg:  tlsCfg,
		handler: securityHeaders(mux),
		store:   st,
	}, nil
}

// Store returns the admin SQLite store.
func (s *Server) Store() *store.Store {
	return s.store
}

func (s *Server) Close() error {
	if s == nil || s.store == nil {
		return nil
	}
	return s.store.Close()
}

func (s *Server) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	serve := func(name, addr string, ln net.Listener) {
		srv := &http.Server{
			Handler:           s.handler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    1 << 14,
		}
		wg.Go(func() {
			slog.Info("listening admin "+name, "addr", addr)
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("admin %s: %w", name, err)
			}
		})
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdownCtx)
			_ = ln.Close()
		}()
	}

	lc := net.ListenConfig{}
	if s.cfg.Listen != "" {
		ln, err := lc.Listen(ctx, "tcp", s.cfg.Listen)
		if err != nil {
			return fmt.Errorf("admin http listen: %w", err)
		}
		serve("http", s.cfg.Listen, ln)
	}
	if s.cfg.HTTPS != "" {
		ln, err := lc.Listen(ctx, "tcp", s.cfg.HTTPS)
		if err != nil {
			return fmt.Errorf("admin https listen: %w", err)
		}
		serve("https", s.cfg.HTTPS, tls.NewListener(ln, s.tlsCfg))
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-ctx.Done():
		<-done
		_ = s.store.SweepSessions()
		return nil
	case err := <-errCh:
		return err
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

func CookieSecure(mode string, hasTLS bool) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	default:
		return hasTLS
	}
}
