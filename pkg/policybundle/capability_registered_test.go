package policybundle

import "testing"

// HAI-493: contracts v0.18.0 registers the postgres provider with the read
// capability query.run, so a postgres plan tool is no longer denied as an
// unregistered capability.
func TestCapabilityRegisteredPostgresQueryRun(t *testing.T) {
	if !capabilityRegistered("postgres", "query.run") {
		t.Fatal(`capabilityRegistered("postgres", "query.run") = false, want true`)
	}
	if capabilityRegistered("postgres", "query.write") {
		t.Fatal(`capabilityRegistered("postgres", "query.write") = true, want false`)
	}
}
