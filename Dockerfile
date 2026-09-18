FROM golang:1.27-alpine AS builder

WORKDIR /build

# git is required to fetch the private connector-contract module, and again at
# build time because the toolchain shells out to `git version`.
RUN apk add --no-cache git

COPY go.mod go.sum ./

# The connector contract is a released module rather than a path copied out of
# the kei tree, so this build no longer depends on that repository's layout. It
# is a private module: pass GITHUB_TOKEN (contents:read on
# HaikeiLabs/kei-connector-contracts) as a build secret, never as a build arg —
# an arg is recorded in the image history.
ENV GOPRIVATE=github.com/HaikeiLabs/*
RUN --mount=type=secret,id=github_token \
    if [ -s /run/secrets/github_token ]; then \
      git config --global url."https://$(cat /run/secrets/github_token)@github.com/".insteadOf "https://github.com/"; \
    fi && \
    go mod download && \
    git config --global --unset-all url."https://$(cat /run/secrets/github_token 2>/dev/null)@github.com/".insteadOf 2>/dev/null || true

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
