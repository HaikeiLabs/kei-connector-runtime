// Package template is a compilable starting point for a new harness adapter.
// Fork this directory and replace the example metadata and native config logic.
package template

import (
	"context"
	"encoding/json"
	"io"

	"github.com/HaikeiLabs/kei-connector-runtime/pkg/harness"
)

const Kind harness.Kind = "example"

type Adapter struct{}

func (Adapter) Kind() harness.Kind { return Kind }

func (Adapter) DiscoverTools(context.Context, harness.Env) (harness.Discovery, error) {
	return harness.Discovery{BuiltIns: []harness.Tool{{
		Name: "example.read", Source: "example", OperationClass: "read", Description: "Read example resources",
	}}}, nil
}

func (Adapter) RenderPolicy(_ context.Context, _ harness.Env, bundle harness.VerifiedBundle, _ harness.Harness) (harness.RenderPlan, error) {
	// Replace this with native config rendering. Keep policy interpretation and
	// authorization in the harness; adapters only render the verified bundle.
	return harness.RenderPlan{ExpiresAt: bundle.ExpiresAt}, nil
}

func (Adapter) Hook(_ context.Context, _ harness.Recorder, _ harness.Harness, in io.Reader, out io.Writer) error {
	// A real hook should decode the harness event and report it to Recorder.
	_, err := io.Copy(io.Discard, in)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]string{"status": "observed"})
}

func DiscoveryGolden() ([]byte, error) {
	discovery, err := (Adapter{}).DiscoverTools(context.Background(), harness.Env{})
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(discovery, "", "  ")
}

var _ harness.Adapter = Adapter{}
