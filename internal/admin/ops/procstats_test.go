// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ops

import (
	"testing"
	"time"

	"github.com/Quad4-Software/ravenguard/internal/config"
)

func TestCollectProcessStats(t *testing.T) {
	st := collectProcessStats(12.5)
	if st.CPUPercent != 12.5 {
		t.Fatalf("cpu_percent=%v", st.CPUPercent)
	}
	if st.NumCPU < 1 {
		t.Fatalf("num_cpu=%d", st.NumCPU)
	}
	if st.GOMAXPROCS < 1 {
		t.Fatalf("gomaxprocs=%d", st.GOMAXPROCS)
	}
	if st.Goroutines < 1 {
		t.Fatalf("goroutines=%d", st.Goroutines)
	}
	if st.HeapAllocBytes == 0 {
		t.Fatal("expected heap_alloc_bytes > 0")
	}
	if st.SysBytes == 0 {
		t.Fatal("expected sys_bytes > 0")
	}
	if st.RSSBytes == 0 {
		t.Fatal("expected rss_bytes > 0")
	}
}

func TestCPUTrackerSamples(t *testing.T) {
	var tr cpuTracker
	if got := tr.samplePercent(); got != 0 {
		t.Fatalf("first sample want 0 got %v", got)
	}
	sum := 0.0
	for i := range 2_000_000 {
		sum += float64(i)
	}
	_ = sum
	time.Sleep(20 * time.Millisecond)
	pct := tr.samplePercent()
	if pct < 0 || pct > 100 {
		t.Fatalf("cpu percent out of range: %v", pct)
	}
	if tr.lastPercent() != pct {
		t.Fatalf("lastPercent=%v sample=%v", tr.lastPercent(), pct)
	}
}

func TestRecordSampleIncludesProcess(t *testing.T) {
	rt := NewRuntime(config.Default(), nil, nil, nil, nil, nil, nil)
	rt.RecordSample()
	rt.RecordSample()
	hist := rt.History()
	if len(hist) < 2 {
		t.Fatalf("history len=%d", len(hist))
	}
	st := rt.Status()
	if st.Process.NumCPU < 1 {
		t.Fatalf("status process num_cpu=%d", st.Process.NumCPU)
	}
	last := hist[len(hist)-1]
	if last.Goroutines < 1 {
		t.Fatalf("sample goroutines=%d", last.Goroutines)
	}
	if last.RSSBytes == 0 && last.HeapAllocBytes == 0 {
		t.Fatal("expected memory fields in sample")
	}
}
