// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package proxyproto

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Listener struct {
	net.Listener
	Timeout time.Duration
}

func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	timeout := l.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &conn{Conn: c, timeout: timeout}, nil
}

type conn struct {
	net.Conn
	timeout time.Duration
	initMu  sync.Mutex
	br      *bufio.Reader
	remote  atomic.Pointer[net.TCPAddr]
	inited  atomic.Bool
}

func (c *conn) RemoteAddr() net.Addr {
	if a := c.remote.Load(); a != nil {
		return a
	}
	return c.Conn.RemoteAddr()
}

func (c *conn) Read(b []byte) (int, error) {
	if err := c.ensure(); err != nil {
		return 0, err
	}
	return c.br.Read(b)
}

func (c *conn) ensure() error {
	if c.inited.Load() {
		return nil
	}
	c.initMu.Lock()
	defer c.initMu.Unlock()
	if c.inited.Load() {
		return nil
	}
	if err := c.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return err
	}
	c.br = bufio.NewReader(c.Conn)
	hdr, err := c.br.Peek(6)
	if err != nil {
		_ = c.SetReadDeadline(time.Time{})
		return err
	}
	if bytes.HasPrefix(hdr, []byte("PROXY ")) {
		line, err := c.br.ReadString('\n')
		_ = c.SetReadDeadline(time.Time{})
		if err != nil {
			return err
		}
		addr, err := parseProxyLine(line)
		if err != nil {
			return err
		}
		if addr != nil {
			c.remote.Store(addr)
		}
		c.inited.Store(true)
		return nil
	}
	_ = c.SetReadDeadline(time.Time{})
	c.inited.Store(true)
	return nil
}

func parseProxyLine(line string) (*net.TCPAddr, error) {
	line = strings.TrimSpace(line)
	parts := strings.Fields(line)
	if len(parts) < 2 || parts[0] != "PROXY" {
		return nil, fmt.Errorf("bad proxy line")
	}
	if parts[1] == "UNKNOWN" {
		return nil, nil
	}
	if len(parts) < 6 {
		return nil, fmt.Errorf("short proxy line")
	}
	ip := net.ParseIP(parts[2])
	if ip == nil {
		return nil, fmt.Errorf("bad src ip")
	}
	var port int
	if _, err := fmt.Sscanf(parts[4], "%d", &port); err != nil {
		return nil, err
	}
	return &net.TCPAddr{IP: ip, Port: port}, nil
}
