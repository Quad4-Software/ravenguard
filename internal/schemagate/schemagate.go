// SPDX-License-Identifier: 0BSD
// Copyright (c) 2026 Quad4

package schemagate

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"

	"github.com/Quad4-Software/ravenguard/internal/bodybuf"
)

// Schema is a compiled OpenAPI document attached to routes.
type Schema struct {
	ID       string
	Name     string
	Mode     string
	SpecText string
}

// Result is the outcome of Validate.
type Result struct {
	OK          bool
	ShouldBlock bool
	Reason      string
	SchemaID    string
}

type compiled struct {
	schema    Schema
	router    routers.Router
	detectOnly bool
}

// Manager holds compiled schemas keyed by id.
type Manager struct {
	mu   sync.RWMutex
	byID map[string]*compiled
}

// NewManager returns an empty manager.
func NewManager() *Manager {
	return &Manager{byID: map[string]*compiled{}}
}

// Replace recompiles all schemas.
func (m *Manager) Replace(schemas []Schema) error {
	next := make(map[string]*compiled, len(schemas))
	for _, s := range schemas {
		c, err := compileSchema(s)
		if err != nil {
			return fmt.Errorf("schema %s: %w", s.ID, err)
		}
		next[s.ID] = c
	}
	m.mu.Lock()
	m.byID = next
	m.mu.Unlock()
	return nil
}

func compileSchema(s Schema) (*compiled, error) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData([]byte(s.SpecText))
	if err != nil {
		return nil, err
	}
	doc.Servers = nil
	if err := doc.Validate(loader.Context); err != nil {
		return nil, err
	}
	rtr, err := gorillamux.NewRouter(doc)
	if err != nil {
		return nil, err
	}
	mode := strings.ToLower(strings.TrimSpace(s.Mode))
	if mode == "" {
		mode = "block"
	}
	s.Mode = mode
	return &compiled{schema: s, router: rtr, detectOnly: mode == "detect"}, nil
}

// Validate checks the request against the schema. Empty schemaID skips.
func (m *Manager) Validate(r *http.Request, schemaID string) Result {
	schemaID = strings.TrimSpace(schemaID)
	if m == nil || schemaID == "" || r == nil {
		return Result{OK: true}
	}
	m.mu.RLock()
	c := m.byID[schemaID]
	m.mu.RUnlock()
	if c == nil {
		return Result{
			OK:          false,
			ShouldBlock: true,
			Reason:      "OpenAPI schema not loaded",
			SchemaID:    schemaID,
		}
	}

	route, pathParams, err := c.router.FindRoute(r)
	if err != nil {
		res := Result{
			OK:       false,
			Reason:   "no matching operation in OpenAPI schema",
			SchemaID: schemaID,
		}
		res.ShouldBlock = !c.detectOnly
		return res
	}

	maxBody := int64(1 << 20)
	if cl := r.ContentLength; cl > 0 && cl < maxBody {
		maxBody = cl
	}
	if _, err := bodybuf.Capture(r, maxBody); err != nil {
		res := Result{
			OK:       false,
			Reason:   "failed to read request body for schema validation",
			SchemaID: schemaID,
		}
		res.ShouldBlock = !c.detectOnly
		return res
	}

	input := &openapi3filter.RequestValidationInput{
		Request:    r,
		PathParams: pathParams,
		Route:      route,
		Options: &openapi3filter.Options{
			// OpenAPI securitySchemes are not enforced at the gateway.
			// Use RavenGuard access policies for auth. Specs that declare
			// security are still validated for shape only.
			AuthenticationFunc: openapi3filter.NoopAuthenticationFunc,
		},
	}
	if err := openapi3filter.ValidateRequest(context.Background(), input); err != nil {
		res := Result{
			OK:       false,
			Reason:   err.Error(),
			SchemaID: schemaID,
		}
		res.ShouldBlock = !c.detectOnly
		return res
	}
	return Result{OK: true, SchemaID: schemaID}
}

// ValidateSpecText compiles a raw OAS document for admin save checks.
func ValidateSpecText(spec string) error {
	_, err := compileSchema(Schema{ID: "tmp", Name: "tmp", Mode: "block", SpecText: spec})
	return err
}
