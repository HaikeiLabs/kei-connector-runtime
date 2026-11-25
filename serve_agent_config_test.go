package connectorruntime

import (
	"context"
	"errors"
	"testing"
	"time"

	keiruntime "github.com/HaikeiLabs/kei-connector-runtime/runtime"
)

// The policy refresher keeps the /v1/agent-config model snapshot current off
// the request path, copying only non-secret fields.
func TestRefreshModelProfileMetadataCopiesOnlyNonSecretFields(t *testing.T) {
	local := keiruntime.NewLocalPDP(Config{RuntimeStateDir: t.TempDir()}, nil)
	defer local.Close()
	profiles := fakeRuntimeProfiles{assigned: &ModelProfile{
		ProfileID: "00000000-0000-4000-8000-00000000b001", DefaultModel: "glm-5.3-flash", Endpoint: "https://models.example/v1",
		AuthType: "api_key", SecretRef: "kei://model-profiles/x/api_key", SecretBackend: "aws-secrets-manager", IsDefault: true, Status: "active",
	}}
	if !local.ModelProfileMetadataDue(time.Now()) {
		t.Fatal("no snapshot yet: refresh must be due")
	}
	refreshModelProfileMetadata(context.Background(), profiles, local)
	if local.ModelProfileMetadataDue(time.Now()) {
		t.Fatal("fresh snapshot still due")
	}
	got := local.ModelProfileMetadataSnapshot()
	want := keiruntime.ModelProfileMetadata{ProfileID: "00000000-0000-4000-8000-00000000b001", Model: "glm-5.3-flash", Endpoint: "https://models.example/v1", IsDefault: true}
	if got == nil || *got != want {
		t.Fatalf("snapshot = %+v, want %+v", got, want)
	}
}

func TestRefreshModelProfileMetadataClearsWhenInactiveKeepsOnError(t *testing.T) {
	for name, tc := range map[string]struct {
		profiles fakeRuntimeProfiles
		keep     bool
	}{
		"transient error keeps": {profiles: fakeRuntimeProfiles{assignedErr: errors.New("boom")}, keep: true},
		"inactive clears":       {profiles: fakeRuntimeProfiles{assigned: &ModelProfile{ProfileID: "p", DefaultModel: "m", Status: "revoked"}}},
	} {
		t.Run(name, func(t *testing.T) {
			local := keiruntime.NewLocalPDP(Config{RuntimeStateDir: t.TempDir()}, nil)
			defer local.Close()
			local.SetModelProfileMetadata(&keiruntime.ModelProfileMetadata{ProfileID: "old", Model: "old"})
			refreshModelProfileMetadata(context.Background(), tc.profiles, local)
			if got := local.ModelProfileMetadataSnapshot(); (got != nil) != tc.keep {
				t.Fatalf("snapshot = %+v, keep = %v", got, tc.keep)
			}
		})
	}
}
