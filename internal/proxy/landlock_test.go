// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package proxy

import (
	"errors"
	"fmt"
	"os"
	"testing"
)

func TestIsLandlockBlocked(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "permission denied string",
			err:  errors.New("dial tcp 127.0.0.1:5280: connect: permission denied"),
			want: true,
		},
		{
			name: "os.ErrPermission wrapper",
			err:  fmt.Errorf("dial: %w", os.ErrPermission),
			want: true,
		},
		{
			name: "connection refused",
			err:  errors.New("dial tcp 127.0.0.1:5280: connect: connection refused"),
			want: false,
		},
		{
			name: "timeout",
			err:  errors.New("i/o timeout"),
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isLandlockBlocked(tc.err); got != tc.want {
				t.Fatalf("isLandlockBlocked(%v) = %v want %v", tc.err, got, tc.want)
			}
		})
	}
}
