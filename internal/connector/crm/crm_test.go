package crm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/HaikeiLabs/kei-connector-contracts/contract"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/connectortest"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector/input"
)

const (
	apiKey  = "fake-crm-connector-key-0000000000000001"
	keyRef  = "kei-prod-runtime-assertion-key"
	backend = "aws-secrets-manager"
	kid     = "kei-rt-66666666-6666-6666-6666-666666666666-1"
)

type store map[string]string

func (s store) Get(_ context.Context, b, r string) (*string, error) {
	v, ok := s[b+"|"+r]
	if !ok {
		return nil, errors.New("not found")
	}
	return &v, nil
}

func newKey(t *testing.T) (*ecdsa.PrivateKey, store) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	return key, store{backend + "|" + keyRef: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))}
}

func crmCall(r *connectortest.Routes, config map[string]any) connector.Call {
	call := connectortest.Call(r, contract.ProviderCRM, "lead.read", contract.ActionRead, "leads", input.Empty{}, apiKey)
	call.Meta.Config = config
	return call
}

var validConfig = map[string]any{"base_url": "https://crm.example.com", "assertion_audience": "kei-crm", "allowed_resources": []any{"leads"}}

func TestLeadReadSignsTheAssertionAndProjectsLeads(t *testing.T) {
	key, st := newKey(t)
	r := connectortest.NewRoutes()
	r.Handle("crm.example.com", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost || req.URL.Path != "/api/crm/v1/invoke" || req.Header.Get("X-KEI-API-Key") != apiKey {
			t.Errorf("request = %s %s", req.Method, req.URL.Path)
		}
		header, claims := verify(t, strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer "), &key.PublicKey)
		if header["kid"] != kid || header["alg"] != "ES256" {
			t.Errorf("header = %v", header)
		}
		if claims["iss"] != "kei-runtime:66666666-6666-6666-6666-666666666666" || claims["aud"] != "kei-crm" ||
			claims["exp"].(float64)-claims["iat"].(float64) != 60 || claims["jti"] == "" || claims["provider"] != "crm" ||
			claims["tenant_id"] != "t-1" || claims["workspace_id"] != "w-1" || claims["capability"] != "lead.read" ||
			claims["resource"] != "leads" || claims["trace_id"] != "trace-1" || claims["connector_status"] != "active" {
			t.Errorf("claims = %v", claims)
		}
		caps := fmt.Sprint(claims["capabilities"])
		if !strings.Contains(caps, "map[action:read name:lead.read requires_approval:false]") || !strings.Contains(caps, "map[action:create name:lead.create requires_approval:true]") {
			t.Errorf("capabilities = %s", caps)
		}
		if fmt.Sprint(claims["policy"]) != "map[allowed_actions:[read] allowed_resources:[leads]]" {
			t.Errorf("policy = %v", claims["policy"])
		}
		_, _ = io.WriteString(w, `{"success":true,"data":{"records":[{"id":7,"company_name":"Acme","email":"ann@acme.test","status":"new","message":"PRIVATE FREE TEXT","early_access_notes":"PRIVATE NOTES"}]}}`)
	})
	got, err := Connector{Store: st, Key: KeyConfig{Backend: backend, Ref: keyRef, KID: kid}}.Execute(context.Background(), crmCall(r, validConfig))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(got)
	if !strings.Contains(string(raw), `"company_name":"Acme"`) || strings.Contains(string(raw), "PRIVATE") {
		t.Fatalf("result = %s", raw)
	}
}

func TestFailsClosedBeforeCallingTheWorker(t *testing.T) {
	_, st := newKey(t)
	good := KeyConfig{Backend: backend, Ref: keyRef, KID: kid}
	cases := []struct {
		name   string
		key    KeyConfig
		config map[string]any
		lookup func(context.Context, string) ([]net.IP, error)
		want   error
	}{
		{"no key configured", KeyConfig{}, validConfig, nil, ErrAssertionKey},
		{"kid without installation id", KeyConfig{Backend: backend, Ref: keyRef, KID: "runtime-key-1"}, validConfig, nil, ErrAssertionKey},
		{"key missing from store", KeyConfig{Backend: backend, Ref: "other", KID: kid}, validConfig, nil, ErrAssertionKey},
		{"no base url", good, map[string]any{"assertion_audience": "kei-crm"}, nil, connector.ErrConfig},
		{"http base url", good, map[string]any{"base_url": "http://crm.example.com", "assertion_audience": "kei-crm"}, nil, connector.ErrConfig},
		{"private address", good, validConfig, func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("10.0.0.5")}, nil }, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := connectortest.NewRoutes()
			call := crmCall(r, tc.config)
			if tc.lookup != nil {
				call.LookupIP = tc.lookup
			}
			_, err := Connector{Store: st, Key: tc.key}.Execute(context.Background(), call)
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if r.Count() != 0 {
				t.Fatal("the Worker was called")
			}
		})
	}
}

func verify(t *testing.T, token string, pub *ecdsa.PublicKey) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %q", token)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(sig) != 64 || !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("signature does not verify")
	}
	decode := func(s string) map[string]any {
		raw, _ := base64.RawURLEncoding.DecodeString(s)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		return m
	}
	return decode(parts[0]), decode(parts[1])
}
