// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package auth

import "testing"

func TestHashVerifyPassword(t *testing.T) {
	hash, err := HashPassword("correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPassword(hash, "correct-horse-battery"); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := VerifyPassword(hash, "wrong-password!!"); err == nil {
		t.Fatal("expected mismatch")
	}
}

func TestRandomPassword(t *testing.T) {
	p, err := RandomPassword(18)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePassword(p); err != nil {
		t.Fatal(err)
	}
}

func TestValidatePassword(t *testing.T) {
	if err := ValidatePassword("short"); err == nil {
		t.Fatal("expected short error")
	}
	if err := ValidatePassword("long-enough-pass"); err != nil {
		t.Fatal(err)
	}
}
