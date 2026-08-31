// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package proxyproto_test

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/proxyproto"
)

func TestProxyV1(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	pln := &proxyproto.Listener{Listener: ln, Timeout: time.Second}

	done := make(chan net.Addr, 1)
	go func() {
		c, err := pln.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		_, _ = io.ReadFull(c, buf)
		done <- c.RemoteAddr()
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, _ = client.Write([]byte("PROXY TCP4 203.0.113.9 10.0.0.1 12345 80\r\nPING"))
	addr := <-done
	tcp, ok := addr.(*net.TCPAddr)
	if !ok || tcp.IP.String() != "203.0.113.9" {
		t.Fatalf("got %v", addr)
	}
}
