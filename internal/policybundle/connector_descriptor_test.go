package policybundle

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

const connectorsExample = "../../docs/contracts/examples/policy-bundle-v2.connectors.payload.example.json"

func connectorsExampleDoc(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(connectorsExample)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func validateConnectorsDoc(t *testing.T, doc map[string]any) (*Verified, error) {
	t.Helper()
	previous := schemaValidatorV2
	SetV2SchemaValidator(v2SchemaValidator(t))
	t.Cleanup(func() { SetV2SchemaValidator(previous) })
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return ValidateV2(raw, v2Installation, v2Org, v2Workspace, 0, time.Date(2026, 10, 5, 12, 30, 0, 0, time.UTC))
}

func TestV2BundleDecodesConnectorDescriptors(t *testing.T) {
	v, err := validateConnectorsDoc(t, connectorsExampleDoc(t))
	if err != nil {
		t.Fatalf("the contract example must validate: %v", err)
	}
	if !v.CarriesConnectorDescriptors() {
		t.Fatal("a v2 bundle with policy_set.connectors must report descriptors")
	}
	crm, ok := v.Connector("conn-crm")
	if !ok || crm.Name != "crm" || crm.Provider != "http_api" || crm.CredentialSource != "opaque_ref" || crm.AccountModel != "shared" ||
		crm.CredentialRef != "kei://connectors/conn-crm/api_key" || crm.CredentialBackend != "aws-secrets-manager" || crm.HTTPAPI == nil ||
		crm.HTTPAPI.CredentialInjection.Name != "Authorization" || len(crm.Capabilities) != 3 {
		t.Fatalf("crm descriptor = %+v, %v", crm, ok)
	}
	github, ok := v.Connector("conn-github")
	if !ok || github.CredentialSource != "oauth" || github.AccountModel != "per_user" || github.CredentialRef != "" || github.CredentialBackend != "" {
		t.Fatalf("github descriptor = %+v, %v", github, ok)
	}
	if _, ok := v.Connector("conn-absent"); ok {
		t.Fatal("an absent connector must not resolve")
	}
}

func TestV2BundleWithoutConnectorsKeepsTodaysBehavior(t *testing.T) {
	doc := connectorsExampleDoc(t)
	delete(doc["policy_set"].(map[string]any), "connectors")
	v, err := validateConnectorsDoc(t, doc)
	if err != nil {
		t.Fatalf("a bundle without connectors must validate: %v", err)
	}
	if v.CarriesConnectorDescriptors() {
		t.Fatal("a bundle without policy_set.connectors must not report descriptors")
	}
	if _, ok := v.Connector("conn-crm"); ok {
		t.Fatal("no descriptor exists without the section")
	}
}

func TestV2ConnectorDescriptorMutationsAreRejected(t *testing.T) {
	cases := map[string]func(crm, github map[string]any){
		"secret-shaped config key":      func(crm, _ map[string]any) { crm["config"] = map[string]any{"api_key": "x"} },
		"token-shaped config key":       func(_, github map[string]any) { github["config"] = map[string]any{"access_token": "x"} },
		"credential_ref is a raw value": func(crm, _ map[string]any) { crm["credential_ref"] = "sk_live_123" },
		"credential_ref is an ARN":      func(crm, _ map[string]any) { crm["credential_ref"] = "arn:aws:secretsmanager:us-west-2:1:secret:x" },
		"unknown descriptor field":      func(crm, _ map[string]any) { crm["credential_secret_ref"] = "aws-secrets-manager://us-west-2/x" },
		"value on credential_injection": func(crm, _ map[string]any) {
			crm["http_api"].(map[string]any)["credential_injection"].(map[string]any)["value"] = "x"
		},
		"oauth with a credential_ref":          func(_, github map[string]any) { github["credential_ref"] = "kei://connectors/conn-github/token" },
		"opaque_ref without a backend":         func(crm, _ map[string]any) { delete(crm, "credential_backend") },
		"http_api that is oauth":               func(crm, _ map[string]any) { crm["credential_source"] = "oauth" },
		"descriptor without credential_source": func(_, github map[string]any) { delete(github, "credential_source") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			doc := connectorsExampleDoc(t)
			connectors := doc["policy_set"].(map[string]any)["connectors"].([]any)
			mutate(connectors[0].(map[string]any), connectors[1].(map[string]any))
			if _, err := validateConnectorsDoc(t, doc); err == nil {
				t.Fatal("mutated descriptor validated")
			} else if errors.Is(err, ErrBundleExpired) {
				t.Fatalf("rejected for the wrong reason: %v", err)
			}
		})
	}
}
