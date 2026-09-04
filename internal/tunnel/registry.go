// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package tunnel

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
)

// Session wraps a yamux session for one connector.
type Session struct {
	ConnectorID string
	sess        *yamux.Session
	streams     atomic.Int32
	closed      atomic.Bool
}

func newSession(connectorID string, conn net.Conn, server bool) (*Session, error) {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 30 * time.Second
	cfg.ConnectionWriteTimeout = 10 * time.Second
	cfg.MaxStreamWindowSize = 256 * 1024
	var ys *yamux.Session
	var err error
	if server {
		ys, err = yamux.Server(conn, cfg)
	} else {
		ys, err = yamux.Client(conn, cfg)
	}
	if err != nil {
		return nil, err
	}
	return &Session{ConnectorID: connectorID, sess: ys}, nil
}

func (s *Session) Close() error {
	if s == nil || s.sess == nil {
		return nil
	}
	if s.closed.Swap(true) {
		return nil
	}
	return s.sess.Close()
}

func (s *Session) IsClosed() bool {
	return s == nil || s.closed.Load() || (s.sess != nil && s.sess.IsClosed())
}

// OpenStream opens a yamux stream and writes the RG1 header.
func (s *Session) OpenStream(upstreamID string) (net.Conn, error) {
	if s == nil || s.IsClosed() {
		return nil, fmt.Errorf("tunnel session closed")
	}
	if int(s.streams.Load()) >= MaxStreams {
		return nil, fmt.Errorf("tunnel stream limit")
	}
	stream, err := s.sess.Open()
	if err != nil {
		return nil, err
	}
	s.streams.Add(1)
	if err := WriteOpenHeader(stream, upstreamID); err != nil {
		_ = stream.Close()
		s.streams.Add(-1)
		return nil, err
	}
	return &countedConn{Conn: stream, onClose: func() { s.streams.Add(-1) }}, nil
}

// AcceptStream accepts the next inbound stream (connector side).
func (s *Session) AcceptStream() (net.Conn, string, error) {
	if s == nil || s.IsClosed() {
		return nil, "", fmt.Errorf("tunnel session closed")
	}
	stream, err := s.sess.Accept()
	if err != nil {
		return nil, "", err
	}
	_ = stream.SetDeadline(time.Now().Add(10 * time.Second))
	id, err := ReadOpenHeader(stream)
	_ = stream.SetDeadline(time.Time{})
	if err != nil {
		_ = stream.Close()
		return nil, "", err
	}
	return stream, id, nil
}

type countedConn struct {
	net.Conn
	onClose func()
	once    sync.Once
}

func (c *countedConn) Close() error {
	c.once.Do(c.onClose)
	return c.Conn.Close()
}

// Registry maps connector_id to live sessions.
type Registry struct {
	mu   sync.RWMutex
	byID map[string]*Session
	gen  map[string]uint64
}

func NewRegistry() *Registry {
	return &Registry{
		byID: make(map[string]*Session),
		gen:  make(map[string]uint64),
	}
}

// Replace installs sess for connectorID and closes any previous session.
func (r *Registry) Replace(connectorID string, sess *Session) {
	r.mu.Lock()
	old := r.byID[connectorID]
	r.byID[connectorID] = sess
	r.gen[connectorID]++
	r.mu.Unlock()
	if old != nil && old != sess {
		_ = old.Close()
	}
}

// Remove deletes sess if it is still the current session.
func (r *Registry) Remove(connectorID string, sess *Session) {
	r.mu.Lock()
	cur := r.byID[connectorID]
	if cur == sess {
		delete(r.byID, connectorID)
	}
	r.mu.Unlock()
	if sess != nil {
		_ = sess.Close()
	}
}

func (r *Registry) Get(connectorID string) (*Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.byID[connectorID]
	if !ok || s == nil || s.IsClosed() {
		return nil, false
	}
	return s, true
}

// Dial opens a stream to connectorID for upstreamID.
func (r *Registry) Dial(connectorID, upstreamID string) (net.Conn, error) {
	s, ok := r.Get(connectorID)
	if !ok {
		return nil, fmt.Errorf("connector offline")
	}
	return s.OpenStream(upstreamID)
}

func (r *Registry) Online() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.byID))
	for id, s := range r.byID {
		if s != nil && !s.IsClosed() {
			out = append(out, id)
		}
	}
	return out
}

// Pipe copies bidirectionally until either side closes.
func Pipe(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		_ = a.Close()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		_ = b.Close()
	}()
	wg.Wait()
}
