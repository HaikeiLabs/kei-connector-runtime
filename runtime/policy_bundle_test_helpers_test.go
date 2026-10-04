package runtime

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/HaikeiLabs/kei-connector-runtime/internal/policybundle"
)

func unsignedExampleBundle(t *testing.T, now time.Time) []byte {
	t.Helper()
	b, err := os.ReadFile("../docs/contracts/examples/policy-bundle-v1.payload.example.json")
	if err != nil {
		t.Fatal(err)
	}
	b = bytes.ReplaceAll(b, []byte("2026-09-28T16:00:00Z"), []byte(now.UTC().Format(time.RFC3339)))
	b = bytes.ReplaceAll(b, []byte("2026-09-29T04:00:00Z"), []byte(now.UTC().Add(12*time.Hour).Format(time.RFC3339)))
	b = bytes.ReplaceAll(b, []byte("search_web"), []byte("web_search"))
	return b
}

func mustActivateTestBundle(t *testing.T, dir string, now time.Time) (*policybundle.Verified, *policybundle.Store) {
	t.Helper()
	bundleBytes := unsignedExampleBundle(t, now)
	store, err := policybundle.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := store.Activate(bundleBytes, "inst-fixture-0001", "org-fixture-0001", "ws-fixture-0001", now)
	if err != nil {
		t.Fatal(err)
	}
	return bundle, store
}

func fixtureBundlePayloadForTest(t *testing.T, now time.Time) []byte {
	t.Helper()
	b := unsignedExampleBundle(t, now)
	var doc struct {
		PolicySet struct {
			Tools []struct {
				Name   string `json:"name"`
				Action string `json:"action"`
			} `json:"tools"`
		} `json:"policy_set"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"web_search": "tool:web_search", "search_wiki": "tool:search_wiki"}
	for name, action := range want {
		found := false
		for _, tool := range doc.PolicySet.Tools {
			if tool.Name == name && tool.Action == action {
				found = true
			}
		}
		if !found {
			t.Fatalf("unsigned test bundle missing exact action mapping %s -> %s", name, action)
		}
	}
	if strings.Contains(string(b), "search_web") {
		t.Fatal("legacy search_web mapping remains in T49 test bundle")
	}
	return b
}
