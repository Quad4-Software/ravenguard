// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package bodybuf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCaptureRestore(t *testing.T) {
	body := "hello-world"
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
	got, err := Capture(r, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Fatalf("got %q", got)
	}
	again, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != body {
		t.Fatalf("replay %q", again)
	}
	Restore(r, got)
	third, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(third) != body {
		t.Fatalf("restore %q", third)
	}
}

func TestCaptureTruncates(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("abcdef"))
	got, err := Capture(r, 3)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abc" {
		t.Fatalf("got %q", got)
	}
}
