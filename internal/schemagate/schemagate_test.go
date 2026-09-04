// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package schemagate

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const sampleSpec = `
openapi: 3.0.3
info:
  title: Sample
  version: 1.0.0
paths:
  /items/{id}:
    get:
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: ok
  /items:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [name]
              properties:
                name:
                  type: string
      responses:
        "201":
          description: created
`

func TestMissingSchemaFailClosed(t *testing.T) {
	m := NewManager()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/items/abc", nil)
	res := m.Validate(req, "missing")
	if res.OK || !res.ShouldBlock {
		t.Fatalf("missing schema must fail closed: %+v", res)
	}
}

func TestValidateAllowAndDeny(t *testing.T) {
	m := NewManager()
	if err := m.Replace([]Schema{{
		ID: "s1", Name: "sample", Mode: "block", SpecText: sampleSpec,
	}}); err != nil {
		t.Fatal(err)
	}

	okReq := httptest.NewRequest(http.MethodGet, "http://example.com/items/abc", nil)
	if res := m.Validate(okReq, "s1"); !res.OK {
		t.Fatalf("expected ok: %+v", res)
	}

	badMethod := httptest.NewRequest(http.MethodDelete, "http://example.com/items/abc", nil)
	if res := m.Validate(badMethod, "s1"); res.OK || !res.ShouldBlock {
		t.Fatalf("expected deny: %+v", res)
	}

	badBody := httptest.NewRequest(http.MethodPost, "http://example.com/items", strings.NewReader(`{}`))
	badBody.Header.Set("Content-Type", "application/json")
	if res := m.Validate(badBody, "s1"); res.OK || !res.ShouldBlock {
		t.Fatalf("expected body deny: %+v", res)
	}

	goodBody := httptest.NewRequest(http.MethodPost, "http://example.com/items", strings.NewReader(`{"name":"x"}`))
	goodBody.Header.Set("Content-Type", "application/json")
	if res := m.Validate(goodBody, "s1"); !res.OK {
		t.Fatalf("expected body ok: %+v", res)
	}
}

func TestDetectMode(t *testing.T) {
	m := NewManager()
	if err := m.Replace([]Schema{{
		ID: "s1", Name: "sample", Mode: "detect", SpecText: sampleSpec,
	}}); err != nil {
		t.Fatal(err)
	}
	bad := httptest.NewRequest(http.MethodDelete, "http://example.com/items/abc", nil)
	res := m.Validate(bad, "s1")
	if res.OK || res.ShouldBlock {
		t.Fatalf("detect should not block: %+v", res)
	}
}
