package skillsrepo

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/HaikeiLabs/kei-connector-contracts/providers"
	"github.com/HaikeiLabs/kei-connector-runtime/internal/connector"
)

func archiveFor(content []byte) providers.SkillsRepoArchive {
	sum := sha256.Sum256(content)
	return providers.SkillsRepoArchive{Format: providers.SkillsRepoArchiveFormat, Digest: "sha256:" + hex.EncodeToString(sum[:]), Size: len(content), Archive: content}
}

func TestVerifyArchiveFailsClosed(t *testing.T) {
	if err := verifyArchive(archiveFor([]byte("tar.gz bytes"))); err != nil {
		t.Fatalf("a matching archive = %v", err)
	}
	cases := map[string]func(*providers.SkillsRepoArchive){
		"digest mismatch": func(a *providers.SkillsRepoArchive) { a.Archive = []byte("other bytes!") },
		"size mismatch":   func(a *providers.SkillsRepoArchive) { a.Size++ },
		"unknown format":  func(a *providers.SkillsRepoArchive) { a.Format = "zip" },
		"bare digest":     func(a *providers.SkillsRepoArchive) { a.Digest = a.Digest[len("sha256:"):] },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := archiveFor([]byte("tar.gz bytes"))
			mutate(&a)
			if err := verifyArchive(a); !errors.Is(err, errInvalidArchive) {
				t.Fatalf("verifyArchive = %v", err)
			}
		})
	}
	over := archiveFor(make([]byte, providers.SkillsRepoMaxArchiveBytes+1))
	if err := verifyArchive(over); !errors.Is(err, connector.ErrTooLarge) {
		t.Fatalf("an archive over the bound = %v", err)
	}
}

func TestMaxResultBytesCoversAFullArchiveOnlyForFetch(t *testing.T) {
	if got := (Connector{}).MaxResultBytes("skills.fetch"); got < 4*providers.SkillsRepoMaxArchiveBytes/3 {
		t.Fatalf("skills.fetch limit = %d", got)
	}
	if got := (Connector{}).MaxResultBytes("skills.list"); got != 0 {
		t.Fatalf("skills.list limit = %d, want the default", got)
	}
}
