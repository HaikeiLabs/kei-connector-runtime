package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

const heartbeatTestConnectorID = "00000000-0000-4000-8000-000000000123"

func TestHeartbeatLoopReportsResolvedConnectorActivations(t *testing.T) {
	client := &scriptedHeartbeatClient{results: []error{nil}}
	loop := testLoop(client, io.Discard)
	loop.ConnectorActivations = func() ([]string, error) {
		return []string{heartbeatTestConnectorID}, nil
	}
	if failure := loop.Tick(context.Background()); failure != nil {
		t.Fatal(failure)
	}
	got := client.reports[0].ConnectorActivations
	if len(got) != 1 || got[0].ConnectorID != heartbeatTestConnectorID {
		t.Fatalf("connector_activations = %+v, want one entry for %s", got, heartbeatTestConnectorID)
	}
	data, err := json.Marshal(client.reports[0])
	if err != nil {
		t.Fatal(err)
	}
	if want := `"connector_activations":[{"connector_id":"` + heartbeatTestConnectorID + `"}]`; !strings.Contains(string(data), want) {
		t.Fatalf("heartbeat payload = %s, want %s", data, want)
	}
}

func TestHeartbeatLoopOmitsConnectorActivationsWithoutResolve(t *testing.T) {
	client := &scriptedHeartbeatClient{results: []error{nil}}
	loop := testLoop(client, io.Discard)
	loop.ConnectorActivations = func() ([]string, error) { return nil, nil }
	if failure := loop.Tick(context.Background()); failure != nil {
		t.Fatal(failure)
	}
	if got := client.reports[0].ConnectorActivations; len(got) != 0 {
		t.Fatalf("connector_activations = %+v, want none", got)
	}
	data, err := json.Marshal(client.reports[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "connector_activations") {
		t.Fatalf("heartbeat payload = %s, want no connector_activations", data)
	}
}

func TestHeartbeatLoopIgnoresBlankConnectorActivations(t *testing.T) {
	client := &scriptedHeartbeatClient{results: []error{nil}}
	loop := testLoop(client, io.Discard)
	loop.ConnectorActivations = func() ([]string, error) { return []string{""}, nil }
	if failure := loop.Tick(context.Background()); failure != nil {
		t.Fatal(failure)
	}
	if got := client.reports[0].ConnectorActivations; len(got) != 0 {
		t.Fatalf("connector_activations = %+v, want none", got)
	}
}

func TestHeartbeatLoopRequeuesConnectorActivationsAfterHeartbeatFailure(t *testing.T) {
	client := &scriptedHeartbeatClient{results: []error{statusFailure(503), nil}}
	loop := testLoop(client, io.Discard)
	loop.ConnectorActivations = func() ([]string, error) {
		return []string{heartbeatTestConnectorID}, nil
	}
	if failure := loop.Tick(context.Background()); failure != nil {
		t.Fatal(failure)
	}
	if client.calls() != 2 {
		t.Fatalf("heartbeat calls = %d, want 2 (transient retry in tick)", client.calls())
	}
	for i, report := range client.reports {
		if len(report.ConnectorActivations) != 1 || report.ConnectorActivations[0].ConnectorID != heartbeatTestConnectorID {
			t.Fatalf("report %d connector_activations = %+v, want %s still queued", i, report.ConnectorActivations, heartbeatTestConnectorID)
		}
	}
	if failure := loop.Tick(context.Background()); failure != nil {
		t.Fatal(failure)
	}
	if got := client.reports[2].ConnectorActivations; len(got) != 0 {
		t.Fatalf("report 2 connector_activations = %+v, want none after the retry succeeded", got)
	}
}

func TestHeartbeatLoopDoesNotRepeatReportedConnectorActivations(t *testing.T) {
	client := &scriptedHeartbeatClient{results: []error{nil}}
	loop := testLoop(client, io.Discard)
	loop.ConnectorActivations = func() ([]string, error) {
		return []string{heartbeatTestConnectorID}, nil
	}
	if failure := loop.Tick(context.Background()); failure != nil {
		t.Fatal(failure)
	}
	if failure := loop.Tick(context.Background()); failure != nil {
		t.Fatal(failure)
	}
	if got := client.reports[1].ConnectorActivations; len(got) != 0 {
		t.Fatalf("second beat connector_activations = %+v, want none after a successful report", got)
	}
}

func TestHeartbeatLoopKeepsBeatingWhenActivationLookupFails(t *testing.T) {
	client := &scriptedHeartbeatClient{results: []error{nil}}
	loop := testLoop(client, io.Discard)
	loop.ConnectorActivations = func() ([]string, error) {
		return nil, errors.New("credential index is malformed")
	}
	if failure := loop.Tick(context.Background()); failure != nil {
		t.Fatal(failure)
	}
	if got := client.reports[0].ConnectorActivations; len(got) != 0 {
		t.Fatalf("connector_activations = %+v, want none", got)
	}
}
