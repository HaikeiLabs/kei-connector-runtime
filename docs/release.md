# Releasing kei-proxy

This is the runbook for publishing a `kei-proxy` release from
kei-connector-runtime. The [README](../README.md#releases) covers what the
workflow does and what it publishes. This page covers how to run it and what
to do when it goes wrong.

## 1. Prerequisites

Check these before you cut a release:

- **Permissions.** To push a tag you need write access to
  `HaikeiLabs/kei-connector-runtime`. To dispatch a release manually you need
  `admin`, which means a repository or organization owner.
- **`gh` authenticated** against github.com (`gh auth status`).
- **`main` is green:** CI runs build, vet, gofmt, and `go test -race`.
- **Release runner online.** The self-hosted `kei-cli-release` runner, shared
  with kei-cli, must be registered and idle. Check
  <https://github.com/HaikeiLabs/kei-connector-runtime/settings/actions/runners>.
- **Signing key present.** The `release` environment must have the
  `GORELEASER_SIGNING_KEY` secret: the GPG key for
  `kei-cli-releases@haikeilabs.com`.
- **Pick the version.** Find the current stable version with
  `git fetch --tags origin && git tag -l 'proxy-v*' --sort=-v:refname | head -3`
  or `curl -fsSL https://kei-cli-releases.s3.us-east-1.amazonaws.com/kei-proxy/latest.txt`.
  Tags that contain `-rc.`, `-alpha.`, or `-beta.` are prereleases. Any other
  suffix is treated as **stable** and moves `latest.txt`.

## 2. Cut the release

Use **one** of the two paths.

### Path A: push a tag (default)

```sh
git fetch origin
git tag proxy-vX.Y.Z origin/main
git push origin proxy-vX.Y.Z
```

Only `proxy-v*` tags trigger this workflow. A plain `vX.Y.Z` tag does
nothing here.

### Path B: manual dispatch (owners only)

```sh
gh workflow run release.yaml -R HaikeiLabs/kei-connector-runtime -f bump=patch   # or minor, major
```

The workflow finds the highest stable `proxy-vX.Y.Z` tag and bumps it
(default `patch`). It then creates and pushes the new tag on the commit it is
running from, normally `main`, and releases it in the same run. That tag push
is made with `GITHUB_TOKEN`, so it does not start a second release run. If
you are not an owner, **Authorize manual release** fails and nothing else
runs.

## 3. Watch the run

```sh
gh run list -R HaikeiLabs/kei-connector-runtime -w release.yaml -L 3
gh run watch -R HaikeiLabs/kei-connector-runtime <run-id> --exit-status
```

| Path | Authorize manual release | Validate tag | Release |
|---|---|---|---|
| Tag push | skipped (expected) | success | success |
| Dispatch by an owner | success | success | success |
| Dispatch by a non-owner | **failure** | skipped | skipped |

**Check the Release job itself, not the run's overall status.** A run whose
Release job was skipped still shows green.

## 4. Verify the release

Artifacts land at `s3://kei-cli-releases/kei-proxy/<version>/`. `<version>`
is the tag without `proxy-v`.

```sh
BASE=https://kei-cli-releases.s3.us-east-1.amazonaws.com/kei-proxy
V=X.Y.Z
curl -fsSL "$BASE/latest.txt"; echo              # stable only: should print $V

A="kei-proxy_${V}_Linux_x86_64.tar.gz"           # or _Linux_arm64, _macOS_x86_64, _macOS_arm64
curl -fsSLO "$BASE/$V/$A"
curl -fsSLO "$BASE/$V/kei-proxy_${V}_checksums.txt"
curl -fsSLO "$BASE/$V/kei-proxy_${V}_checksums.txt.sig"
shasum -a 256 -c --ignore-missing "kei-proxy_${V}_checksums.txt"   # Linux: sha256sum -c --ignore-missing
# If you have the kei-cli-releases@haikeilabs.com public key imported:
gpg --verify "kei-proxy_${V}_checksums.txt.sig" "kei-proxy_${V}_checksums.txt"
tar -xzf "$A" kei-proxy && ./kei-proxy version
```

### Ship it in kei-cli

A proxy release is not included in `kei` installs until kei-cli's pin is
raised and a CLI release is cut:

```sh
gh variable set KEI_PROXY_VERSION -R HaikeiLabs/kei-cli --body "v$V"
```

Then follow kei-cli's `docs/release.md`. The kei-cli Release job checks that
`kei-proxy/<version>/kei-proxy_<version>_Linux_x86_64.tar.gz` exists before it
builds.

## 5. If something goes wrong

### Release job skipped

- **Validate tag failed.** Usually the tag is not
  `proxy-vMAJOR.MINOR.PATCH[-prerelease]`, or on a dispatch the calculated
  tag already exists. For a bad pushed tag, delete it
  (`git push origin :refs/tags/<tag>` and `git tag -d <tag>`) and push a
  correct one.
- **Authorize manual release failed.** The person who dispatched is not an
  owner. Ask an owner to dispatch, or use Path A.
- **Everything except Authorize manual release was skipped on a tag push.**
  That is the bug fixed in #35. The workflow runs from the tagged commit's
  copy of `release.yaml`, so a tag on a commit older than #35 still has the
  bug. Retag a commit that includes the fix, or dispatch.

### Release job failed

| Step | Likely cause | Fix |
|---|---|---|
| Create and push release tag | Tag appeared since validation, or token lacks `contents: write` | See "Retrying a dispatch" below |
| Import GPG signing key / Verify GPG key | `GORELEASER_SIGNING_KEY` missing, expired, or not for `kei-cli-releases@haikeilabs.com` | Fix the secret in the `release` environment |
| Validate runner AWS identity | Runner Pod lost its IRSA role | Fix the runner deployment |
| Validate S3 bucket accessibility | Role lacks `s3:ListBucket` on the `kei-proxy/` prefix | Fix the IAM policy |
| Run Goreleaser | Build error (including `go mod verify`), or upload denied | Read the GoReleaser output |
| Verify no credentials leaked | A credential pattern appeared in checksums or `install.sh`, or the checksums file is missing | **Stop** if it is a leak. Treat it as an incident before retrying |

A failure before **Run Goreleaser** publishes nothing. Fix the cause, then
retry:

- **Tag push:** rerun the failed job from the run page, or with
  `gh run rerun <run-id> --failed -R HaikeiLabs/kei-connector-runtime`.
- **Retrying a dispatch:** if the log shows the `proxy-v` tag was pushed,
  don't rerun. The rerun fails at *Create and push release tag* because the
  tag already exists. Don't dispatch on top of it either: that bumps to the
  next version and leaves a gap. Delete the tag, then dispatch again, which
  calculates the same version:

  ```sh
  git push origin :refs/tags/proxy-vX.Y.Z
  gh workflow run release.yaml -R HaikeiLabs/kei-connector-runtime -f bump=patch
  ```

  Alternatively, delete the tag and re-push it yourself (Path A).

A failure during or after **Run Goreleaser** may leave a partial
`kei-proxy/<version>/` directory in S3. `latest.txt` is written last, so
installs of "latest" are not affected. Retrying the same version overwrites
the same keys. If you would rather abandon the version, release the next
patch instead. kei-cli only picks up a proxy version when its pin is raised,
so a half-published proxy version is not bundled anywhere.

## History

Before #35 (merged 2026-09-26), the Release job had `needs: [validate-tag]`
and no `if:`. A job without `if:` gets an implicit `success()`, which checks
the whole `needs` chain. On a tag push, Authorize manual release is skipped,
so Release was skipped too: a pushed `proxy-v*` tag would have run Validate
tag, skipped Release, and still shown a green run. All 20 proxy release runs
before the fix were manual dispatches. #35 added
`if: ${{ always() && needs.validate-tag.result == 'success' }}` to Release.
It also limited Validate tag to accepting a skipped authorization only on
push events, so a dispatch still requires an owner. kei-cli had the same bug,
fixed in HaikeiLabs/kei-cli#44.
