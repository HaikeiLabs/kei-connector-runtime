package policybundle

import (
	"testing"
)

func TestToolServiceComesFromVerifiedBundle(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	inst, org, ws := audience()
	verified, err := store.Activate(fixtureBundle(t), inst, org, ws, fixtureNow())
	if err != nil {
		t.Fatal(err)
	}
	if got := verified.ToolService("github.get_issue"); got != "github" {
		t.Fatalf("ToolService(github.get_issue) = %q, want github", got)
	}
	if got := verified.ToolService("search_web"); got != "" {
		t.Fatalf("ToolService(search_web) = %q, want empty", got)
	}
}
