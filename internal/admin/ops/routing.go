// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package ops

import (
	"context"
	"errors"
)

var ErrCertRenewUnavailable = errors.New("cert renew unavailable")
var ErrACMEManageUnavailable = errors.New("acme manage unavailable")
var ErrManualCertUnavailable = errors.New("manual cert unavailable")

// ReloadRouting invokes the wired route reload callback if present.
func (r *Runtime) ReloadRouting() error {
	if r == nil || r.ReloadRoutes == nil {
		return nil
	}
	return r.ReloadRoutes()
}

// CertStatusView returns ACME certificate status if wired.
func (r *Runtime) CertStatusView() any {
	if r == nil || r.CertStatus == nil {
		return []any{}
	}
	return r.CertStatus()
}

// RenewCert renews a managed certificate host if wired.
func (r *Runtime) RenewCert(ctx context.Context, host string) error {
	if r == nil || r.CertRenew == nil {
		return ErrCertRenewUnavailable
	}
	return r.CertRenew(ctx, host)
}

// LogsView returns a log ring snapshot if wired.
func (r *Runtime) LogsView(limit int, level string) any {
	if r == nil || r.LogSnapshot == nil {
		return []any{}
	}
	return r.LogSnapshot(limit, level)
}

// PutManualCert stores a manual PEM certificate if wired.
func (r *Runtime) PutManualCert(hostname, certPEM, keyPEM string) error {
	if r == nil || r.ManualCertPut == nil {
		return ErrManualCertUnavailable
	}
	return r.ManualCertPut(hostname, certPEM, keyPEM)
}

// DeleteManualCert removes a manual certificate if wired.
func (r *Runtime) DeleteManualCert(hostname string) error {
	if r == nil || r.ManualCertDelete == nil {
		return ErrManualCertUnavailable
	}
	return r.ManualCertDelete(hostname)
}

// CertDetailView returns one certificate detail if wired.
func (r *Runtime) CertDetailView(hostname string) (any, error) {
	if r == nil || r.CertDetail == nil {
		return nil, errors.New("cert detail unavailable")
	}
	return r.CertDetail(hostname)
}

// ManageACMEHosts starts ACME management for hosts if wired.
func (r *Runtime) ManageACMEHosts(ctx context.Context, hosts []string) error {
	if r == nil || r.ACMEManage == nil {
		return ErrACMEManageUnavailable
	}
	return r.ACMEManage(ctx, hosts)
}
