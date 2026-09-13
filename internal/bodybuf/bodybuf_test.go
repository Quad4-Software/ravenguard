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

// Regression: Capture used to replace r.Body with only the captured prefix,
// so bodies larger than the inspection cap reached upstream truncated.
func TestCaptureOversizePreservesFullStream(t *testing.T) {
	body := "abcdefghijklmnopqrstuvwxyz"
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(body))
	got, err := Capture(r, 8)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abcdefgh" {
		t.Fatalf("captured prefix %q", got)
	}
	rest, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(rest) != body {
		t.Fatalf("upstream stream truncated: %q", rest)
	}
}

func TestCaptureZeroMaxLeavesBody(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("data"))
	got, err := Capture(r, 0)
	if err != nil || got != nil {
		t.Fatalf("got=%q err=%v", got, err)
	}
	rest, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(rest) != "data" {
		t.Fatalf("body changed: %q", rest)
	}
}
