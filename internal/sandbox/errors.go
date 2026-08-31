// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

//go:build !linux

package sandbox

import "fmt"

func errUnsupported(feature string) error {
	return fmt.Errorf("%s is only supported on linux", feature)
}
