package run

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/credentials"
)

// HAI-1066 (B4): POST /v1/commands:run resolves a kei://connectors/<id>/<field>
// reference to an opaque_ref connector whose credential is the customer's own
// secret (an external credential_ref, HAI-1000), once credential sync has
// resolved it into the connector reference index as an External entry for
// that connector and field. The same fail-closed checks as a Kei-delivered
// secret apply, and the value and its location never leave the child.

const (
	runExternalBareRef = "customer/crm/api-key"
	runExternalRef     = "aws-secrets-manager:///" + runExternalBareRef
)

// newRunExternalRig is the descriptor rig with the index holding an External
// entry for the connector's api_key field instead of a Kei-delivered one.
func newRunExternalRig(t *testing.T, descriptorRef string, entry credentials.ConnectorReference) *runDescriptorRig {
	t.Helper()
	rig := newRunDescriptorRig(t)
	if err := os.Remove(rig.index); err != nil {
		t.Fatal(err)
	}
	if err := credentials.WriteConnectorReference(rig.index, entry); err != nil {
		t.Fatal(err)
	}
	rig.store.values = map[string]string{runDescriptorBackend + "|" + runExternalRef: runDescriptorSentinel}
	rig.grant.Connector.CredentialRef = descriptorRef
	return rig
}

func runExternalEntry() credentials.ConnectorReference {
	return credentials.ConnectorReference{ConnectorID: runDescriptorConnector, Field: "api_key", SecretBackend: runDescriptorBackend, SecretRef: runExternalRef, External: true}
}

func (rig *runDescriptorRig) assertNoExternalLeak(out runOutcome) {
	rig.t.Helper()
	rig.assertNoLeak(out)
	for name, text := range map[string]string{"socket stream": out.raw + out.stdout + out.stderr, "audit": strings.Join(rig.audit, "\n")} {
		if strings.Contains(text, runExternalBareRef) {
			rig.t.Fatalf("%s leaked the external secret's location:\n%s", name, text)
		}
	}
}

func TestDaemonRunResolvesExternalRef(t *testing.T) {
	for name, descriptorRef := range map[string]string{
		// The catalog names every opaque_ref by its kei:// reference.
		"descriptor names the kei reference": runDescriptorRef,
		// SecretResolver also accepts the external ref itself on a descriptor.
		"descriptor names the external bare ref": runExternalBareRef,
	} {
		t.Run(name, func(t *testing.T) {
			rig := newRunExternalRig(t, descriptorRef, runExternalEntry())
			out := rig.run()
			if out.done.Decision != "allow" || out.done.ExitCode != 0 {
				t.Fatalf("done = %+v\n%s", out.done, out.raw)
			}
			if !strings.Contains(out.stdout, fmt.Sprintf("len=%d", len(runDescriptorSentinel))) || !strings.Contains(out.stdout, "raw=[REDACTED]") {
				t.Fatalf("child did not receive the external credential: %q", out.stdout)
			}
			if rig.store.calls != 1 {
				t.Fatalf("store reads = %d, want 1", rig.store.calls)
			}
			rig.assertNoExternalLeak(out)
		})
	}
}

func TestDaemonRunExternalRefDenyMatrix(t *testing.T) {
	for name, tc := range map[string]struct {
		descriptorRef string
		entry         credentials.ConnectorReference
		want          string
	}{
		"external ref never resolved by sync": {runExternalBareRef, credentials.ConnectorReference{
			ConnectorID: runDescriptorConnector, Field: "other_key", SecretBackend: runDescriptorBackend, SecretRef: runExternalRef, External: true,
		}, "unresolved_reference"},
		"index entry is not external": {runExternalBareRef, credentials.ConnectorReference{
			ConnectorID: runDescriptorConnector, Field: "api_key", SecretBackend: runDescriptorBackend, SecretRef: runDescriptorSecretRef, Generation: 1,
		}, "unresolved_reference"},
		"external entry names another secret": {runExternalBareRef, credentials.ConnectorReference{
			ConnectorID: runDescriptorConnector, Field: "api_key", SecretBackend: runDescriptorBackend, SecretRef: "aws-secrets-manager:///customer/other", External: true,
		}, "unresolved_reference"},
		"external entry in another backend": {runExternalBareRef, credentials.ConnectorReference{
			ConnectorID: runDescriptorConnector, Field: "api_key", SecretBackend: "azure-key-vault", SecretRef: "https://acme.vault.azure.net/secrets/crm-dsn", External: true,
		}, "credential_backend_mismatch"},
		"descriptor names a URL-shaped ref": {"https://evil.example/" + runExternalBareRef, runExternalEntry(), "unresolved_reference"},
	} {
		t.Run(name, func(t *testing.T) {
			rig := newRunExternalRig(t, tc.descriptorRef, tc.entry)
			out := rig.run()
			if out.done.Decision != "deny" || out.done.ReasonCode != tc.want {
				t.Fatalf("done = %+v, want deny %s", out.done, tc.want)
			}
			if _, err := os.Stat(rig.marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("the child ran on a deny")
			}
			rig.assertNoExternalLeak(out)
		})
	}
}
