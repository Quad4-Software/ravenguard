// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package listener

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/Quad4-Software/ravenguard/internal/proxyproto"
)

type Config struct {
	HTTP             string
	HTTPS            string
	QUIC             string
	CertFile         string
	KeyFile          string
	TLSConfig        *tls.Config
	Handler          http.Handler
	ProxyProtocol    bool
	MaxHeaderBytes   int
	DisableMultipath bool
}

type Server struct {
	cfg Config
}

func New(cfg Config) *Server {
	return &Server{cfg: cfg}
}

func (s *Server) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	errCh := make(chan error, 3)

	tlsCfg, err := s.loadTLS()
	if err != nil {
		return err
	}

	if s.cfg.HTTP != "" {
		ln, err := s.listenTCP(s.cfg.HTTP)
		if err != nil {
			return fmt.Errorf("http listen: %w", err)
		}
		ln = s.wrap(ln)
		srv := &http.Server{
			Handler:           s.cfg.Handler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    s.maxHeaderBytes(),
		}
		wg.Go(func() {
			log.Printf("listening http on %s", s.cfg.HTTP)
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("http: %w", err)
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

	if s.cfg.HTTPS != "" {
		if tlsCfg == nil {
			return fmt.Errorf("tls required for https")
		}
		ln, err := s.listenTCP(s.cfg.HTTPS)
		if err != nil {
			return fmt.Errorf("https listen: %w", err)
		}
		ln = s.wrap(ln)
		httpsTLS := tlsCfg.Clone()
		httpsTLS.NextProtos = appendALPN(httpsTLS.NextProtos, "h2", "http/1.1")
		srv := &http.Server{
			Handler:           withAltSvc(s.cfg.Handler, s.cfg.QUIC),
			TLSConfig:         httpsTLS,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    s.maxHeaderBytes(),
		}
		tlsLn := tls.NewListener(ln, httpsTLS)
		wg.Go(func() {
			log.Printf("listening https on %s", s.cfg.HTTPS)
			if err := srv.Serve(tlsLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- fmt.Errorf("https: %w", err)
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

	if s.cfg.QUIC != "" {
		if tlsCfg == nil {
			return fmt.Errorf("tls required for quic")
		}
		h3tls := tlsCfg.Clone()
		h3tls.NextProtos = []string{http3.NextProtoH3}
		h3 := &http3.Server{
			Addr:      s.cfg.QUIC,
			Handler:   s.cfg.Handler,
			TLSConfig: h3tls,
		}
		wg.Go(func() {
			log.Printf("listening quic/http3 on %s", s.cfg.QUIC)
			if err := h3.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				errCh <- fmt.Errorf("quic: %w", err)
			}
		})
		go func() {
			<-ctx.Done()
			_ = h3.Close()
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case err := <-errCh:
		return err
	case <-done:
		return nil
	case <-ctx.Done():
		<-done
		return nil
	}
}

func (s *Server) listenTCP(addr string) (net.Listener, error) {
	lc := net.ListenConfig{}
	if s.cfg.DisableMultipath {
		lc.SetMultipathTCP(false)
	}
	return lc.Listen(context.Background(), "tcp", addr)
}

func (s *Server) maxHeaderBytes() int {
	if s.cfg.MaxHeaderBytes > 0 {
		return s.cfg.MaxHeaderBytes
	}
	return 1 << 14
}

func (s *Server) wrap(ln net.Listener) net.Listener {
	if !s.cfg.ProxyProtocol {
		return ln
	}
	return &proxyproto.Listener{Listener: ln}
}

func (s *Server) loadTLS() (*tls.Config, error) {
	if s.cfg.TLSConfig != nil {
		return s.cfg.TLSConfig.Clone(), nil
	}
	if s.cfg.CertFile == "" || s.cfg.KeyFile == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(s.cfg.CertFile, s.cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func appendALPN(existing []string, extras ...string) []string {
	seen := make(map[string]struct{}, len(existing)+len(extras))
	out := make([]string, 0, len(existing)+len(extras))
	for _, p := range existing {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, p := range extras {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func withAltSvc(next http.Handler, quicAddr string) http.Handler {
	if quicAddr == "" {
		return next
	}
	port := quicAddr
	if _, p, err := net.SplitHostPort(quicAddr); err == nil {
		port = p
	}
	alt := fmt.Sprintf(`h3=":%s"; ma=86400`, port)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", alt)
		next.ServeHTTP(w, r)
	})
}
