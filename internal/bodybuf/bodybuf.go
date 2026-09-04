// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package bodybuf

import (
	"bytes"
	"io"
	"net/http"
)

// Capture reads up to maxBytes from r.Body, replaces r.Body with a replayable
// reader, and returns the captured bytes. maxBytes <= 0 means no capture.
func Capture(r *http.Request, maxBytes int64) ([]byte, error) {
	if r == nil || r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	if maxBytes <= 0 {
		return nil, nil
	}
	limited := io.LimitReader(r.Body, maxBytes+1)
	buf, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	_ = r.Body.Close()
	if int64(len(buf)) > maxBytes {
		buf = buf[:maxBytes]
	}
	r.Body = io.NopCloser(bytes.NewReader(buf))
	r.ContentLength = int64(len(buf))
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf)), nil
	}
	return buf, nil
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
