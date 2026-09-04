// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ops

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/agentprotocol"
	"github.com/Quad4-Software/ravenguard/internal/config"
)

func TestRuntimeDispatcherHandleCoreOps(t *testing.T) {
	cfg := config.Default()
	cfg.Challenge.Secret = "test-secret-16chars"
	rt := NewRuntime(cfg, nil, nil, nil, nil, nil, nil)
	rt.LogSnapshot = func(limit int, level string) any {
		return []any{map[string]any{"limit": limit, "level": level}}
	}
	rt.CertStatus = func() any { return map[string]any{"certs": []any{}} }
	rt.CertDetail = func(host string) (any, error) { return map[string]string{"host": host}, nil }
	rt.ManualCertPut = func(host, cert, key string) error { return nil }
	rt.ManualCertDelete = func(host string) error { return nil }
	rt.CertExport = func(host string) (string, string, error) { return "c", "k", nil }
	rt.CertRenew = func(ctx context.Context, host string) error { return nil }
	rt.ACMEManage = func(ctx context.Context, hosts []string) error { return nil }

	d := &RuntimeDispatcher{
		Runtime: rt,
		ApplyRouting: func(ctx context.Context, raw json.RawMessage) error {
			return nil
		},
		ApplyDesired: func(ctx context.Context, state agentprotocol.DesiredState) error {
			return nil
		},
	}
	ctx := context.Background()

	cases := []struct {
		op      string
		payload string
	}{
		{agentprotocol.OpHeartbeat, `{}`},
		{agentprotocol.OpStatus, `{}`},
		{agentprotocol.OpStatusHistory, `{}`},
		{agentprotocol.OpConfigSafeGet, `{}`},
		{agentprotocol.OpConfigSafePut, `{}`},
		{agentprotocol.OpRoutingPut, `{}`},
		{agentprotocol.OpDesiredApply, `{"revision":2}`},
		{agentprotocol.OpBansList, `{}`},
		{agentprotocol.OpBlocklistsGet, `{}`},
		{agentprotocol.OpQFeedsGet, `{}`},
		{agentprotocol.OpLogsSnapshot, `{"limit":10,"level":"info"}`},
		{agentprotocol.OpCertsStatus, `{}`},
		{agentprotocol.OpCertsDetail, `{"host":"ex.test"}`},
		{agentprotocol.OpCertsPut, `{"host":"ex.test","cert_pem":"c","key_pem":"k"}`},
		{agentprotocol.OpCertsDelete, `{"host":"ex.test"}`},
		{agentprotocol.OpCertsExport, `{"host":"ex.test"}`},
		{agentprotocol.OpCertsRenew, `{"host":"ex.test"}`},
		{agentprotocol.OpCertsManage, `{"hosts":["ex.test"]}`},
	}
	for _, tc := range cases {
		if _, err := d.Handle(ctx, tc.op, json.RawMessage(tc.payload)); err != nil {
			t.Fatalf("%s: %v", tc.op, err)
		}
	}
	if _, err := d.Handle(ctx, "nope.op", nil); err == nil {
		t.Fatal("expected unknown op")
	}
	if _, err := (*RuntimeDispatcher)(nil).Handle(ctx, agentprotocol.OpStatus, nil); err == nil {
		t.Fatal("expected nil dispatcher error")
	}
}

func TestRuntimeDispatcherMissingDeps(t *testing.T) {
	cfg := config.Default()
	cfg.Challenge.Secret = "test-secret-16chars"
	rt := NewRuntime(cfg, nil, nil, nil, nil, nil, nil)
	d := &RuntimeDispatcher{Runtime: rt}
	ctx := context.Background()

	if _, err := d.Handle(ctx, agentprotocol.OpRoutingPut, json.RawMessage(`{}`)); err == nil {
		t.Fatal("expected routing unavailable")
	}
	if _, err := d.Handle(ctx, agentprotocol.OpBansCreate, json.RawMessage(`{"key":"1.1.1.1"}`)); err == nil {
		t.Fatal("expected protect disabled")
	}
	if _, err := d.Handle(ctx, agentprotocol.OpBansDelete, json.RawMessage(`{"key":"1.1.1.1"}`)); err == nil {
		t.Fatal("expected protect disabled")
	}
	if _, err := d.Handle(ctx, agentprotocol.OpBlocklistsReload, nil); err == nil {
		t.Fatal("expected blocklists unavailable")
	}
	if _, err := d.Handle(ctx, agentprotocol.OpBlocklistsAdd, json.RawMessage(`{"kind":"ip","value":"1.1.1.1"}`)); err == nil {
		t.Fatal("expected blocklists unavailable")
	}
	if _, err := d.Handle(ctx, agentprotocol.OpBlocklistsRemove, json.RawMessage(`{"kind":"ip","value":"1.1.1.1"}`)); err == nil {
		t.Fatal("expected blocklists unavailable")
	}
	if _, err := d.Handle(ctx, agentprotocol.OpQFeedsRefresh, nil); err == nil {
		t.Fatal("expected qfeeds unavailable")
	}
	if _, err := d.Handle(ctx, agentprotocol.OpCertsDetail, json.RawMessage(`{"host":"x"}`)); err == nil {
		t.Fatal("expected certs unavailable")
	}
}
