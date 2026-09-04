// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ops

import (
	"context"
	"testing"

	"github.com/Quad4-Software/ravenguard/internal/agentprotocol"
	"github.com/Quad4-Software/ravenguard/internal/config"
)

func TestOfflineTargetNeverLeaksLocal(t *testing.T) {
	cfg := config.Default()
	cfg.Challenge.Secret = "test-secret-16chars"
	rt := NewRuntime(cfg, nil, nil, nil, nil, nil, nil)
	local := &LocalTarget{Runtime: rt}
	offline := &OfflineTarget{ProxyID: "edge-1"}
	ctx := context.Background()

	if _, err := offline.Status(ctx); err == nil {
		t.Fatal("expected offline error")
	}
	if _, err := offline.History(ctx); err == nil {
		t.Fatal("expected offline history error")
	}
	if err := offline.ApplySafeConfig(ctx, SafeConfig{}); err == nil {
		t.Fatal("expected offline apply safe error")
	}
	if _, err := offline.Call(ctx, agentprotocol.OpStatus, nil); err == nil {
		t.Fatal("expected offline call error")
	}
	st, err := local.Status(ctx)
	if err != nil || st == nil {
		t.Fatalf("local status: %v %v", st, err)
	}
	if _, err := local.History(ctx); err != nil {
		t.Fatal(err)
	}
	if err := local.ApplyDesired(ctx, agentprotocol.DesiredState{Revision: 1}); err != nil {
		t.Fatal(err)
	}
	if err := local.ApplyDesired(ctx, agentprotocol.DesiredState{
		Revision:   2,
		SafeConfig: []byte(`{}`),
	}); err != nil {
		t.Fatal(err)
	}
	env, err := local.Call(ctx, agentprotocol.OpStatus, nil)
	if err != nil || env.OK == nil || !*env.OK {
		t.Fatalf("local call: %+v %v", env, err)
	}
	if err := offline.ApplyDesired(ctx, agentprotocol.DesiredState{Revision: 1}); err == nil {
		t.Fatal("expected offline apply error")
	}
	remote := &RemoteTarget{}
	if _, err := remote.Call(ctx, agentprotocol.OpStatus, nil); err == nil {
		t.Fatal("expected remote unavailable")
	}
}
