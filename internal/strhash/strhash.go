// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package strhash

// String returns FNV-1a 32-bit hash of s without allocating.
func String(s string) uint32 {
	const (
		offset32 = 2166136261
		prime32  = 16777619
	)
	h := uint32(offset32)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= prime32
	}
	return h
}
