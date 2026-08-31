// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package challenge_test

import (
	"net/http"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/challenge"
)

func TestStubCaptcha(t *testing.T) {
	v, err := challenge.NewCaptcha("stub", "ok")
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(&http.Request{}, "ok"); err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(&http.Request{}, "no"); err == nil {
		t.Fatal("expected fail")
	}
	if _, err := challenge.NewCaptcha("hcaptcha", ""); err == nil {
		t.Fatal("expected unsupported")
	}
}
