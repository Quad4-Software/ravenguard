// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package bodybuf

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func FuzzCapture(f *testing.F) {
	f.Add([]byte("hello"), int64(1024))
	f.Add([]byte(""), int64(0))
	f.Add([]byte("abcdef"), int64(3))
	f.Fuzz(func(t *testing.T, body []byte, maxBytes int64) {
		if maxBytes < 0 {
			maxBytes = -maxBytes
		}
		if maxBytes > 1<<20 {
			maxBytes = 1 << 20
		}
		r := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		got, err := Capture(r, maxBytes)
		if err != nil {
			t.Fatal(err)
		}
		if maxBytes <= 0 {
			if got != nil {
				t.Fatalf("expected nil got %q", got)
			}
			return
		}
		wantLen := len(body)
		if int64(wantLen) > maxBytes {
			wantLen = int(maxBytes)
		}
		if len(got) != wantLen {
			t.Fatalf("len=%d want %d", len(got), wantLen)
		}
		again, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(again, got) {
			t.Fatalf("replay mismatch")
		}
		Restore(r, got)
		third, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(third, got) {
			t.Fatalf("restore mismatch")
		}
	})
}
