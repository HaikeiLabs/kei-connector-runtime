// Package connectortest holds test fixtures shared by the connector
// packages: an in-process transport that routes provider requests by host,
// and a Call builder. It never touches the network.
package connectortest

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector"
)

// Routes serves provider requests from handlers keyed by host.
type Routes struct {
	mu       sync.Mutex
	handlers map[string]http.HandlerFunc
	requests []*http.Request
}

// NewRoutes returns an empty route table.
func NewRoutes() *Routes { return &Routes{handlers: map[string]http.HandlerFunc{}} }

// Handle serves host with h.
func (r *Routes) Handle(host string, h http.HandlerFunc) { r.handlers[host] = h }

// RoundTrip implements http.RoundTripper.
func (r *Routes) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.requests = append(r.requests, req)
	h, ok := r.handlers[req.URL.Host]
	r.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("no fixture for host %s", req.URL.Host)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec.Result(), nil
}

// Count returns how many requests were made.
func (r *Routes) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.requests)
}

// Client returns an http.Client over the routes.
func (r *Routes) Client() *http.Client { return &http.Client{Transport: r} }

// PublicLookup resolves every host to one public address.
func PublicLookup(context.Context, string) ([]net.IP, error) {
	return []net.IP{net.ParseIP("93.184.216.34")}, nil
}

// Call builds a connector.Call for provider with the given capabilities.
func Call(routes *Routes, provider contract.Provider, capability string, action contract.Action, resource string, in any, credential string) connector.Call {
	meta := contract.Metadata{
		ID: "44444444-4444-4444-4444-444444444444", TenantID: "t-1", WorkspaceID: "w-1", Name: "conn",
		Provider: provider, Status: contract.StatusActive, CredentialSource: contract.CredentialSourceOpaqueRef,
		CredentialRef: "kei-prod-connector-4444", Scopes: []string{"read"}, Resources: []string{"*"},
		Capabilities: contract.CapabilitiesFor(provider), CreatedBy: "u-1",
	}
	inv := contract.Invocation{
		TenantID: "t-1", WorkspaceID: "w-1", Subject: "55555555-5555-5555-5555-555555555555",
		AgentID: "33333333-3333-3333-3333-333333333333", ConnectorID: meta.ID,
		Capability: capability, Action: action, Resource: resource, TraceID: "trace-1",
	}
	return connector.Call{
		Meta: meta, Invocation: inv, Input: in, Credential: credential,
		HTTPClient: routes.Client(), LookupIP: PublicLookup,
		Now: func() time.Time { return time.Unix(1_790_000_000, 0).UTC() },
	}
}
