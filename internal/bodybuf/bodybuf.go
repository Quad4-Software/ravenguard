// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package bodybuf

import (
	"bytes"
	"io"
	"net/http"
	"sync"
)

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 4096)
		return &b
	},
}

// Capture reads up to maxBytes from r.Body for inspection and returns them.
// r.Body is left so the request still delivers the complete original stream:
// when the body fits under maxBytes it becomes a replayable reader over the
// captured bytes, and when it exceeds the cap the captured prefix is chained
// back in front of the unread remainder. maxBytes <= 0 means no capture.
func Capture(r *http.Request, maxBytes int64) ([]byte, error) {
	if r == nil || r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	if maxBytes <= 0 {
		return nil, nil
	}
	bp := bufPool.Get().(*[]byte)
	buf := (*bp)[:0]
	limited := io.LimitReader(r.Body, maxBytes+1)
	var err error
	buf, err = readAllAppend(buf, limited)
	if err != nil {
		*bp = buf[:0]
		bufPool.Put(bp)
		return nil, err
	}
	if int64(len(buf)) <= maxBytes {
		_ = r.Body.Close()
		out := append([]byte(nil), buf...)
		*bp = buf[:0]
		bufPool.Put(bp)
		r.Body = io.NopCloser(bytes.NewReader(out))
		r.ContentLength = int64(len(out))
		r.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(out)), nil
		}
		return out, nil
	}
	// The body is larger than the inspection cap. Keep the whole stream intact
	// for the upstream while handing the caller only the captured prefix.
	head := append([]byte(nil), buf...)
	*bp = buf[:0]
	bufPool.Put(bp)
	orig := r.Body
	r.Body = &joinedBody{Reader: io.MultiReader(bytes.NewReader(head), orig), Closer: orig}
	r.GetBody = nil
	return head[:maxBytes], nil
}

type joinedBody struct {
	io.Reader
	io.Closer
}

func readAllAppend(dst []byte, r io.Reader) ([]byte, error) {
	const chunk = 32 * 1024
	for {
		if cap(dst)-len(dst) < chunk {
			dst = append(dst, make([]byte, chunk)...)
			dst = dst[:len(dst)-chunk]
		}
		n, err := r.Read(dst[len(dst):cap(dst)])
		dst = dst[:len(dst)+n]
		if err != nil {
			if err == io.EOF {
				return dst, nil
			}
			return dst, err
		}
	}
}

// Restore sets r.Body to a fresh reader over buf.
func Restore(r *http.Request, buf []byte) {
	if r == nil {
		return
	}
	if len(buf) == 0 {
		r.Body = http.NoBody
		r.ContentLength = 0
		r.GetBody = nil
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(buf))
	r.ContentLength = int64(len(buf))
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf)), nil
	}
}
