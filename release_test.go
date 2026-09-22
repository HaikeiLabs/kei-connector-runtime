package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuntimeDaemonReleaseConfigStaticValidation(t *testing.T) {
	root := "."
	config := readReleaseFile(t, filepath.Join(root, ".goreleaser.yaml"))
	for _, want := range []string{
		"project_name: kei-proxy", "dir: .", "main.version={{.Version}}",
		"- -X main.commit={{.Commit}}", "- -X main.date={{.Date}}", "- darwin", "- linux",
		"- amd64", "- arm64", "formats: [tar.gz]", "algorithm: sha256", "detach-sign",
		"directory: \"kei-proxy/{{ .Version }}\"", "disable: true",
	} {
		if !strings.Contains(config, want) {
			t.Errorf("GoReleaser config missing %q", want)
		}
	}
}

func TestRuntimeDaemonInstallScriptStaticValidation(t *testing.T) {
	path := filepath.Join("scripts", "install.sh")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("installer is not executable: %s", path)
	}
	src := readReleaseFile(t, path)
	for _, want := range []string{
		"set -euo pipefail", "AWS_S3_RELEASES_URL_BASE", "Darwin", "Linux", "x86_64", "arm64",
		"shasum -a 256", "-v VERSION", "kei-proxy/latest.txt",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("installer missing %q", want)
		}
	}
	if out, err := exec.Command("bash", "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("bash -n failed: %v\n%s", err, out)
	}
}

func TestRuntimeDaemonReleaseWorkflowStaticValidation(t *testing.T) {
	path := filepath.Join(".github", "workflows", "release.yaml")
	src := readReleaseFile(t, path)
	for _, want := range []string{
		"proxy-v*", "workflow_dispatch:", "bump:", "default: patch", "patch", "minor", "major",
		"authorize_manual_release:", "Require repository or organization owner",
		"LATEST_TAG=\"$(git tag --list 'proxy-v*'", "INPUT_BUMP", "proxy-v0.0.1",
		"proxy-v${MAJOR}.${MINOR}.${PATCH}", "runs-on: kei-cli-release", "AWS_S3_RELEASES_BUCKET",
		"AWS_S3_RELEASES_REGION", "goreleaser/goreleaser-action@v6", ".goreleaser.yaml",
		"kei-proxy/", "scripts/install.sh", "kei-proxy/install.sh", "channel=$CHANNEL",
		"GORELEASER_SIGNING_KEY",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("connector-runtime release workflow missing %q", want)
		}
	}
	if got := strings.Count(src, "runs-on: kei-cli-release"); got != 3 {
		t.Errorf("expected authorization, validate-tag, and release jobs to use kei-cli-release, found %d", got)
	}
	for _, stale := range []string{"kei-eks-deploy", "kei-ecs-deploy"} {
		if strings.Contains(src, stale) {
			t.Errorf("release workflow contains stale runner label %q", stale)
		}
	}
	if strings.Contains(src, "id-token: write") || strings.Contains(src, "configure-aws-credentials") {
		t.Error("connector-runtime release workflow must rely on runner IRSA, not GitHub OIDC")
	}
	if !strings.Contains(src, "if: needs.validate-tag.outputs.channel == 'stable'") {
		t.Error("latest.txt upload must be limited to stable releases")
	}
	for _, leak := range []string{"AWS_ACCESS_KEY_ID=", "AWS_SECRET_ACCESS_KEY=", "AWS_SESSION_TOKEN="} {
		if strings.Contains(src, leak) {
			t.Errorf("workflow contains static credential assignment %q", leak)
		}
	}
}

func readReleaseFile(t *testing.T, path string) string {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(src)
}
