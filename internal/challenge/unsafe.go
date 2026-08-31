// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package challenge

import "unsafe"

func stringBytes(s string) []byte {
	if s == "" {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(s), len(s)) // #nosec G103
}
