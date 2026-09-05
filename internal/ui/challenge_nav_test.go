// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ui_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Guards the post-clearance navigation fix: same-URL location.replace is a no-op
// in many browsers, so challenge.js must reload when next matches the interstitial.
func TestChallengeJSReloadsSameDocument(t *testing.T) {
	t.Parallel()
	path := filepath.Join("static", "challenge.js")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	if !strings.Contains(src, "isSameDocument") {
		t.Fatal("challenge.js missing isSameDocument helper")
	}
	if !strings.Contains(src, "location.reload") {
		t.Fatal("challenge.js must reload when next equals the interstitial URL")
	}
	if !strings.Contains(src, "location.replace") {
		t.Fatal("challenge.js should still replace when next differs")
	}
	obf, err := os.ReadFile(filepath.Join("static", "c.js"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(obf), "reload") {
		t.Fatal("obfuscated c.js must retain reload for same-document clearance")
	}
}
