// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ops

import (
	"runtime"
	"sync"
	"time"
)

// ProcessStats is live process resource usage for the admin overview.
type ProcessStats struct {
	CPUPercent     float64 `json:"cpu_percent"`
	Goroutines     int     `json:"goroutines"`
	GOMAXPROCS     int     `json:"gomaxprocs"`
	NumCPU         int     `json:"num_cpu"`
	HeapAllocBytes uint64  `json:"heap_alloc_bytes"`
	HeapSysBytes   uint64  `json:"heap_sys_bytes"`
	SysBytes       uint64  `json:"sys_bytes"`
	RSSBytes       uint64  `json:"rss_bytes"`
	GCPauseNs      uint64  `json:"gc_pause_ns"`
	NumGC          uint32  `json:"num_gc"`
}

type cpuTracker struct {
	mu       sync.Mutex
	lastSec  float64
	lastWall time.Time
	lastPct  float64
}

func (t *cpuTracker) lastPercent() float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastPct
}

func (t *cpuTracker) samplePercent() float64 {
	sec, err := processCPUSeconds()
	if err != nil {
		return t.lastPercent()
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.lastWall.IsZero() {
		t.lastSec = sec
		t.lastWall = now
		t.lastPct = 0
		return 0
	}
	dCPU := sec - t.lastSec
	dWall := now.Sub(t.lastWall).Seconds()
	t.lastSec = sec
	t.lastWall = now
	if dWall <= 0 || dCPU < 0 {
		return t.lastPct
	}
	ncpu := float64(runtime.NumCPU())
	if ncpu < 1 {
		ncpu = 1
	}
	pct := (dCPU / dWall / ncpu) * 100
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	t.lastPct = pct
	return pct
}

func collectProcessStats(cpuPct float64) ProcessStats {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	pause := uint64(0)
	if ms.NumGC > 0 {
		pause = ms.PauseNs[(ms.NumGC+255)%256]
	}
	st := ProcessStats{
		CPUPercent:     cpuPct,
		Goroutines:     runtime.NumGoroutine(),
		GOMAXPROCS:     runtime.GOMAXPROCS(0),
		NumCPU:         runtime.NumCPU(),
		HeapAllocBytes: ms.HeapAlloc,
		HeapSysBytes:   ms.HeapSys,
		SysBytes:       ms.Sys,
		RSSBytes:       processRSSBytes(),
		GCPauseNs:      pause,
		NumGC:          ms.NumGC,
	}
	if st.RSSBytes == 0 {
		st.RSSBytes = ms.Sys
	}
	return st
}
