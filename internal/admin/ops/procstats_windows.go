// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

//go:build windows

package ops

import "errors"

func processCPUSeconds() (float64, error) {
	return 0, errors.New("cpu sample unavailable on windows")
}

func processRSSBytes() uint64 {
	return 0
}
