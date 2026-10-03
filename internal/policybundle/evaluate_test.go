package policybundle

import "testing"

func TestBareSelectorsMatchLegacyGroupAndToolActionNames(t *testing.T) {
	if !srcMatch("read", Call{}, []string{"read"}, nil) {
		t.Fatal("bare source selector did not match its exact group name")
	}
	if !dstMatch("web_search", Call{Action: "web_search"}, tool{Name: "web_search", Action: "web_search"}) {
		t.Fatal("bare destination selector did not match its exact tool action")
	}
}
