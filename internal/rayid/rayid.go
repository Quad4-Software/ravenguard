// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package rayid

import (
	"encoding/binary"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

var counter atomic.Uint64

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 48)
		return &b
	},
}

const hexdigits = "0123456789abcdef"

func New() string {
	var rb [8]byte
	binary.LittleEndian.PutUint64(rb[:], rand.Uint64()) //nolint:gosec // G404 ray id is not a cryptographic secret
	n := counter.Add(1)
	ts := uint64(time.Now().UnixNano()) // #nosec G115

	bp := bufPool.Get().(*[]byte)
	buf := (*bp)[:0]
	buf = appendHexU64(buf, ts)
	buf = appendHexU64(buf, n)
	buf = appendHexBytes(buf, rb[:])
	out := string(buf)
	*bp = buf[:0]
	bufPool.Put(bp)
	return out
}

func appendHexU64(dst []byte, v uint64) []byte {
	var buf [16]byte
	for i := 15; i >= 0; i-- {
		buf[i] = hexdigits[v&0xf]
		v >>= 4
	}
	return append(dst, buf[:]...)
}

func appendHexBytes(dst, src []byte) []byte {
	for _, b := range src {
		dst = append(dst, hexdigits[b>>4], hexdigits[b&0xf])
	}
	return dst
}
