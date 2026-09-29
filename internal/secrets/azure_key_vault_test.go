package secrets

import "testing"

func TestParseKeyVaultSecretRef(t *testing.T) {
	vault, name, version, err := parseKeyVaultSecretRef("https://demo.vault.azure.net/secrets/github-token/v1")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if vault != "https://demo.vault.azure.net" || name != "github-token" || version != "v1" {
		t.Fatalf("got vault=%q name=%q version=%q", vault, name, version)
	}
}

func TestParseKeyVaultSecretRefRejectsInvalidRefs(t *testing.T) {
	for _, ref := range []string{
		"http://demo.vault.azure.net/secrets/token",
		"https://demo.vault.azure.net/not-secrets/token",
		"https://demo.vault.azure.net/secrets/",
		"https://demo.vault.azure.net/secrets/token/v1/extra",
	} {
		if _, _, _, err := parseKeyVaultSecretRef(ref); err == nil {
			t.Errorf("parseKeyVaultSecretRef(%q) succeeded", ref)
		}
	}
}
