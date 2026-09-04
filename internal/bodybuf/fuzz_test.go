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
	f.Fuzz(func(t *testing.T, body []byte, max int64) {
		if max < 0 {
			max = -max
		}
		if max > 1<<20 {
			max = 1 << 20
		}
		r := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(body))
		got, err := Capture(r, max)
		if err != nil {
			t.Fatal(err)
		}
		if max <= 0 {
			if got != nil {
				t.Fatalf("expected nil got %q", got)
			}
			return
		}
		wantLen := len(body)
		if int64(wantLen) > max {
			wantLen = int(max)
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
