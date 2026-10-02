package template

import (
	"bytes"
	"os"
	"testing"
)

func TestDiscoveryGolden(t *testing.T) {
	got, err := DiscoveryGolden()
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	want, err := os.ReadFile("testdata/discovery.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("discovery differs from golden\n got: %s\nwant: %s", got, want)
	}
}
