// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package challenge

import (
	"errors"
	"net/http"
	"strings"
)

var ErrCaptchaFailed = errors.New("captcha verification failed")

type StubCaptcha struct {
	Token string
}

func (s StubCaptcha) Verify(_ *http.Request, token string) error {
	want := s.Token
	if want == "" {
		want = "ok"
	}
	if strings.TrimSpace(token) != want {
		return ErrCaptchaFailed
	}
	return nil
}

func NewCaptcha(provider, token string) (CaptchaVerifier, error) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "stub":
		return StubCaptcha{Token: token}, nil
	default:
		return nil, ErrCaptchaNeeded
	}
}
