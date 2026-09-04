// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/tlscerts"
)

type certGenerateFlags struct {
	Hosts    string
	CertPath string
	KeyPath  string
	Validity string
	Force    bool
}

func parseCertGenerateFlags(args []string) (certGenerateFlags, error) {
	fs := flag.NewFlagSet("cert generate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var f certGenerateFlags
	fs.StringVar(&f.Hosts, "hosts", "localhost,127.0.0.1", "comma-separated DNS names and/or IP SANs")
	fs.StringVar(&f.CertPath, "cert", "./certs/fullchain.pem", "output certificate PEM path")
	fs.StringVar(&f.KeyPath, "key", "./certs/privkey.pem", "output private key PEM path")
	fs.StringVar(&f.Validity, "validity", "365d", "certificate lifetime (Go duration or Nd days)")
	fs.BoolVar(&f.Force, "force", false, "overwrite existing cert and key files")
	if err := fs.Parse(args); err != nil {
		return f, err
	}
	if fs.NArg() != 0 {
		return f, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	return f, nil
}

func parseValidity(s string) (time.Duration, error) {
	return tlscerts.ParseValidity(s)
}

func runCert(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: ravenguard cert generate [flags]")
		return 2
	}
	switch args[0] {
	case "generate":
		return runCertGenerate(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown cert subcommand %q\n", args[0])
		fmt.Fprintln(os.Stderr, "usage: ravenguard cert generate [flags]")
		return 2
	}
}

func runCertGenerate(args []string) int {
	f, err := parseCertGenerateFlags(args)
	if err != nil {
		return 2
	}
	validity, err := parseValidity(f.Validity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cert generate: %v\n", err)
		return 1
	}
	hosts := splitCSV(f.Hosts)
	if len(hosts) == 0 {
		fmt.Fprintln(os.Stderr, "cert generate: at least one host is required")
		return 1
	}
	certPEM, keyPEM, err := tlscerts.Generate(tlscerts.GenerateOptions{
		Hosts:    hosts,
		Validity: validity,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cert generate: %v\n", err)
		return 1
	}
	if err := tlscerts.WriteFiles(f.CertPath, f.KeyPath, certPEM, keyPEM, f.Force); err != nil {
		fmt.Fprintf(os.Stderr, "cert generate: %v\n", err)
		return 1
	}
	fmt.Printf("wrote certificate %s\n", f.CertPath)
	fmt.Printf("wrote private key %s\n", f.KeyPath)
	return 0
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
