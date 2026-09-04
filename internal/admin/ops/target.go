// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ops

import (
	"context"
	"encoding/json"

	"github.com/Quad4-Software/ravenguard/internal/agentprotocol"
)

// ProxyTarget is the admin façade for local or remote proxy operations.
type ProxyTarget interface {
	Status(ctx context.Context) (any, error)
	History(ctx context.Context) (any, error)
	ApplySafeConfig(ctx context.Context, safe SafeConfig) error
	ApplyDesired(ctx context.Context, state agentprotocol.DesiredState) error
	Call(ctx context.Context, op string, payload any) (agentprotocol.Envelope, error)
}

// LocalTarget wraps an in-process Runtime (combined / single-proxy mode).
type LocalTarget struct {
	Runtime        *Runtime
	ApplyDesiredFn func(ctx context.Context, state agentprotocol.DesiredState) error
}

func (t *LocalTarget) Status(ctx context.Context) (any, error) {
	_ = ctx
	if t == nil || t.Runtime == nil {
		return nil, errUnavailable("runtime")
	}
	return t.Runtime.Status(), nil
}

func (t *LocalTarget) History(ctx context.Context) (any, error) {
	_ = ctx
	if t == nil || t.Runtime == nil {
		return nil, errUnavailable("runtime")
	}
	return t.Runtime.History(), nil
}

func (t *LocalTarget) ApplySafeConfig(ctx context.Context, safe SafeConfig) error {
	_ = ctx
	if t == nil || t.Runtime == nil {
		return errUnavailable("runtime")
	}
	return t.Runtime.ApplySafeConfig(safe)
}

func (t *LocalTarget) ApplyDesired(ctx context.Context, state agentprotocol.DesiredState) error {
	if t != nil && t.ApplyDesiredFn != nil {
		return t.ApplyDesiredFn(ctx, state)
	}
	if len(state.SafeConfig) > 0 && t != nil && t.Runtime != nil {
		safe, err := DecodeSafeConfig(string(state.SafeConfig))
		if err != nil {
			var s SafeConfig
			if uerr := json.Unmarshal(state.SafeConfig, &s); uerr != nil {
				return err
			}
			safe = s
		}
		return t.Runtime.ApplySafeConfig(safe)
	}
	return nil
}

func (t *LocalTarget) Call(ctx context.Context, op string, payload any) (agentprotocol.Envelope, error) {
	d := &RuntimeDispatcher{Runtime: t.Runtime, ApplyDesired: t.ApplyDesiredFn}
	var raw json.RawMessage
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return agentprotocol.Envelope{}, err
		}
		raw = b
	}
	out, err := d.Handle(ctx, op, raw)
	env := agentprotocol.Envelope{V: agentprotocol.ProtocolVersion, Op: op}
	if err != nil {
		f := false
		env.OK = &f
		env.Error = err.Error()
		return env, err
	}
	ok := true
	env.OK = &ok
	if out != nil {
		env.Payload, _ = json.Marshal(out)
	}
	return env, nil
}

// RemoteTarget talks to a connected agent via the hub registry.
type RemoteTarget struct {
	Registry *agentprotocol.Registry
	ProxyID  string
}

func (t *RemoteTarget) Status(ctx context.Context) (any, error) {
	env, err := t.Call(ctx, agentprotocol.OpStatus, nil)
	if err != nil {
		return nil, err
	}
	var v any
	_ = json.Unmarshal(env.Payload, &v)
	return v, nil
}

func (t *RemoteTarget) History(ctx context.Context) (any, error) {
	env, err := t.Call(ctx, agentprotocol.OpStatusHistory, nil)
	if err != nil {
		return nil, err
	}
	var v any
	_ = json.Unmarshal(env.Payload, &v)
	return v, nil
}

func (t *RemoteTarget) ApplySafeConfig(ctx context.Context, safe SafeConfig) error {
	_, err := t.Call(ctx, agentprotocol.OpConfigSafePut, safe)
	return err
}

func (t *RemoteTarget) ApplyDesired(ctx context.Context, state agentprotocol.DesiredState) error {
	_, err := t.Call(ctx, agentprotocol.OpDesiredApply, state)
	return err
}

func (t *RemoteTarget) Call(ctx context.Context, op string, payload any) (agentprotocol.Envelope, error) {
	if t == nil || t.Registry == nil || t.ProxyID == "" {
		return agentprotocol.Envelope{}, errUnavailable("proxy")
	}
	return t.Registry.Call(ctx, t.ProxyID, op, payload)
}

// OfflineTarget refuses ops when a fleet proxy is not connected.
type OfflineTarget struct {
	ProxyID string
}

func (t *OfflineTarget) Status(ctx context.Context) (any, error) {
	_ = ctx
	return nil, errUnavailable("proxy offline")
}

func (t *OfflineTarget) History(ctx context.Context) (any, error) {
	_ = ctx
	return nil, errUnavailable("proxy offline")
}

func (t *OfflineTarget) ApplySafeConfig(ctx context.Context, safe SafeConfig) error {
	_ = ctx
	_ = safe
	return errUnavailable("proxy offline")
}

func (t *OfflineTarget) ApplyDesired(ctx context.Context, state agentprotocol.DesiredState) error {
	_ = ctx
	_ = state
	return errUnavailable("proxy offline")
}

func (t *OfflineTarget) Call(ctx context.Context, op string, payload any) (agentprotocol.Envelope, error) {
	_ = ctx
	_ = op
	_ = payload
	return agentprotocol.Envelope{}, errUnavailable("proxy offline")
}

type targetError string

func (e targetError) Error() string { return string(e) }

func errUnavailable(what string) error {
	return targetError(what + " unavailable")
}
