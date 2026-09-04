// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package faststr

import "unsafe"

func unsafeStringBytes(s string) []byte {
	if s == "" {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(s), len(s)) // #nosec G103
}
