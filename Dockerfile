FROM golang:1.27-alpine AS builder

WORKDIR /build

# git is required to fetch the private connector-contract module, and again at
# build time because the toolchain shells out to `git version`.
RUN apk add --no-cache git

COPY go.mod go.sum ./

# The connector contract is a released module rather than a path copied out of
# the kei tree, so this build no longer depends on that repository's layout. It
# is a private module: pass the token (contents:read on
# HaikeiLabs/kei-connector-contracts) as a build secret, never as a build arg —
# an arg is recorded in the image history.
#
# GOPRIVATE names the single module rather than a wildcard, so only this one
# path bypasses the public proxy and checksum database.
ENV GOPRIVATE=github.com/HaikeiLabs/kei-connector-contracts
# The x-access-token username is required for a GitHub App installation token.
# A bare https://TOKEN@github.com/ works for a classic PAT but fails for an App
# token, and the App is the credential this build is expected to receive.
#
# git config is written inside the RUN rather than persisted: the credential
# lives only in this layer's execution, and the layer records the config file's
# absence, not the token.
RUN --mount=type=secret,id=github_token \
    if [ -s /run/secrets/github_token ]; then \
      git config --global \
        url."https://x-access-token:$(cat /run/secrets/github_token)@github.com/".insteadOf \
        "https://github.com/"; \
    fi && \
    go mod download && \
    rm -f /root/.gitconfig

COPY . .

# The binary keeps the name kei-proxy. Kei-Chat-Harness resolves it through
# KEI_PROXY_PATH and kei-cli through exec.LookPath("kei-proxy") with a
# /tmp/kei-proxy fallback, and it is published under the kei-proxy/ S3 release
# prefix. ADR-017 treats those as external contracts, not cosmetics: renaming
# the artifact is gated separately from renaming the service.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o kei-proxy .

FROM alpine:3.19

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /build/kei-proxy .

ENTRYPOINT ["./kei-proxy"]
