// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

//go:build !linux

package sandbox

func applySeccomp(_ SeccompConfig, _ Mode) (string, error) {
	return "", errUnsupported("seccomp")
}
