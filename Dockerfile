FROM golang:1.27-alpine AS builder

WORKDIR /build

# The Go toolchain shells out to `git version` during the build.
RUN apk add --no-cache git

COPY go.mod go.sum ./

# The connector contract is a released public module
# (github.com/HaikeiLabs/kei-connector-contracts, Apache 2.0), so this build
# needs no credential and no GOPRIVATE: it resolves through the public module
# proxy and is verified against the public checksum database.
RUN go mod download

COPY . .

# GO_TAGS is empty for release images; make image-e2e passes the e2e tag,
# which compiles the private upstream allowance (ADR-036 §10) into the binary.
ARG GO_TAGS

# The binary keeps the name kei-proxy. kei-chat-harness resolves it through
# KEI_PROXY_PATH and kei-cli through exec.LookPath("kei-proxy") with a
# /tmp/kei-proxy fallback, and it is published under the kei-proxy/ S3 release
# prefix. ADR-017 treats those as external contracts, not cosmetics: renaming
# the artifact is gated separately from renaming the service.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags "$GO_TAGS" -o kei-proxy ./cmd/kei-proxy

FROM alpine:3.19

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /build/kei-proxy .

ENTRYPOINT ["./kei-proxy"]
