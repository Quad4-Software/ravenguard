// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package main

import (
	"strings"
	"testing"
	"time"
)

func TestParseValidity(t *testing.T) {
	d, err := parseValidity("365d")
	if err != nil || d != 365*24*time.Hour {
		t.Fatalf("365d: %v %v", d, err)
	}
	d, err = parseValidity("48h")
	if err != nil || d != 48*time.Hour {
		t.Fatalf("48h: %v %v", d, err)
	}
	if _, err := parseValidity("nope"); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseCertGenerateFlags(t *testing.T) {
	f, err := parseCertGenerateFlags([]string{
		"-hosts", "a.example,b.example",
		"-cert", "/tmp/c.pem",
		"-key", "/tmp/k.pem",
		"-validity", "30d",
		"-force",
	})
	if err != nil {
		t.Fatal(err)
	}
	if f.Hosts != "a.example,b.example" || f.CertPath != "/tmp/c.pem" || f.KeyPath != "/tmp/k.pem" || f.Validity != "30d" || !f.Force {
		t.Fatalf("%#v", f)
	}
	hosts := splitCSV(f.Hosts)
	if len(hosts) != 2 || hosts[0] != "a.example" {
		t.Fatalf("%v", hosts)
	}
}

func TestSplitCSV(t *testing.T) {
	got := splitCSV(" a , ,b ")
	if strings.Join(got, "|") != "a|b" {
		t.Fatalf("%v", got)
	}
}
