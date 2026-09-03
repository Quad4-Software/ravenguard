// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

//go:build unix

package ops

import (
	"fmt"
	"os"
	"syscall"
)

func processCPUSeconds() (float64, error) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, err
	}
	return timevalSeconds(ru.Utime) + timevalSeconds(ru.Stime), nil
}

func timevalSeconds(tv syscall.Timeval) float64 {
	return float64(tv.Sec) + float64(tv.Usec)/1e6
}

func processRSSBytes() uint64 {
	b, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	var size, rss uint64
	if _, err := fmt.Sscanf(string(b), "%d %d", &size, &rss); err != nil {
		return 0
	}
	ps := os.Getpagesize()
	if ps <= 0 {
		return 0
	}
	page := uint64(ps) // #nosec G115 -- Getpagesize is a small positive OS constant
	return rss * page
}
