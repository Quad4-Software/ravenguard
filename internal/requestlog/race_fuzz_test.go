// SPDX-License-Identifier: LicenseRef-QSL-1.0-0BSD
// Copyright (c) 2026 Quad4

package requestlog

import (
	"sync"
	"testing"
)

func TestLoggerRaceRecordRecent(t *testing.T) {
	l := New(64)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := range 200 {
				reqID := string(rune('a'+(n%26))) + string(rune('0'+j%10))
				l.Record(Event{RequestID: reqID, Action: ActionBlock, Reason: "x", BindID: "b1"})
				_ = l.Recent(20)
				_, _ = l.GetByID(reqID)
			}
		}(i)
	}
	wg.Wait()
}

func FuzzLoggerRecord(f *testing.F) {
	f.Add("ray1", "bind-a", "reason")
	f.Add("", "bind-a", "reason")
	f.Add("ray2", "", "block")
	f.Fuzz(func(t *testing.T, reqID, bind, reason string) {
		l := New(8)
		l.Record(Event{RequestID: reqID, Action: ActionBlock, Reason: reason, BindID: bind})
		l.Record(Event{RequestID: reqID, Action: ActionChallenge, Reason: reason + "2", BindID: bind})
		if bind != "" {
			l.Record(Event{RequestID: reqID, Action: ActionBlock, Reason: "spoof", BindID: bind + "-other"})
		}
		_, _ = l.GetByID(reqID)
		_ = l.Recent(5)
	})
}
