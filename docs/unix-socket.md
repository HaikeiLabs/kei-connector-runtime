# Why kei-proxy serves over a Unix socket

`kei-proxy serve` exposes its HTTP/1.1 API on a Unix domain socket. The default
path depends on the operating system: `/run/kei-proxy/runtime.sock` on Linux,
`$TMPDIR/kei-proxy/runtime.sock` on macOS (falls back to `os.TempDir()`).
Override with `KEI_RUNTIME_SOCKET_PATH`. The runtime creates the socket with
mode `0600`, refuses to replace an active socket or a regular file, replaces a
stale socket left behind by a crash, and removes the socket on graceful
shutdown. Requests over the socket still go through bearer authentication and
model authorization. The socket changes how the harness reaches the proxy, not
what the harness is allowed to do.

There are three reasons for this design.

## 1. Speed

A harness talks to the runtime frequently — readiness probes, model profile
lookups, and chat requests — so per-request latency adds up over an agent run.
Traffic on a Unix socket stays inside the kernel. There is no TCP handshake,
no loopback routing, no TLS negotiation, and no Nagle or congestion-control
behavior. Each request costs one local IPC round trip.

## 2. Simplicity

The address is just a file path, so there is no port to choose, reserve,
or collide on. The protocol is still plain HTTP/1.1, so harnesses can use any
ordinary HTTP client with a Unix-socket dialer, for example
`curl --unix-socket /run/kei-proxy/runtime.sock http://localhost/readyz`.
Nothing new needs to be framed or versioned. Startup and shutdown are also
simple: the socket appears when the runtime is ready to accept connections
and disappears when it stops.

## 3. kei-proxy is a runtime daemon

`kei-proxy serve` is a long-running daemon that exposes its HTTP/1.1 API on a
Unix domain socket. Harness processes on the same host connect to that socket
to reach the local API: health, readiness, model profile, and chat-completion
routes. The daemon hosts both the PDP and the PEP, so every governed tool
invocation is decided and enforced locally without a subprocess or a catalog
round trip. The daemon and the harness run
independently: the daemon provides the local API, the harness connects to it.

This daemon-socket model brings three benefits:

- **Nothing is exposed on the network.** Because the socket is a file on a
  local filesystem, there is no listening port to secure, no TLS certificate
  to issue or rotate, and no network policy to write.
- **Access control comes from the filesystem.** The mode (`0600`) and owner of
  the socket path decide who can connect. Only processes running as the
  runtime's OS user can open it.
- **No port management.** The address is just a file path. There is no port to
  choose, reserve, or collide on.

### API surface

The socket serves `GET /healthz`, `GET /readyz`, `GET /v1/models`,
`POST /v1/chat/completions`, `POST /v1/authorize`, and
`PUT/DELETE/GET /v1/session`. Governed tool authorization — the PEP — uses
the local PDP on the socket (PRs #78, #79, #80 merged). The legacy
`kei-proxy authorize` CLI subprocess is deprecated; it delegates PDP to the
remote catalog and is retained for harnesses that have not yet migrated.

Both the PEP and the PDP run in the same daemon process. The PDP evaluates
policy locally from an unsigned canonical JSON bundle (ADR-026), and the PEP
enforces the result on every governed invocation without a round trip to the
catalog. The socket route proposed in the closed PR #65 was rejected because
it called the catalog authorize endpoint per request and did not authenticate
the caller.

### Session credentials (`KEI_CREDENTIAL_RELEASE=identity`)

With `KEI_CREDENTIAL_RELEASE=identity` (default `legacy`, which changes
nothing), a `PUT /v1/session` that resolves a linked subject makes one call to
the identity service's `POST /api/v1/connectorCredentials:resolve` (ADR-032 I11)
with the runtime token and the subject's token in `X-Kei-Subject-Token`. The
call goes to `KEI_CREDENTIAL_RELEASE_URL`, or to the runtime control plane when
that is unset. The connector credentials it returns live only in the daemon's
memory (ADR-034, owner option A). Every PUT, `DELETE /v1/session`, a revocation
and daemon exit zero and drop them. A provider 401 triggers one single-provider
re-fetch and one retry, and after that the call is denied. The daemon sets
`RLIMIT_CORE=0` so it never core-dumps them.

**No socket route returns a credential.** The harness holds the same runtime
token as any socket client, so anything on the socket reaches the harness.
Credentialed work runs inside the daemon instead: `POST /v1/connectors:invoke`
(L3b) and `POST /v1/commands:run` (L3c) are coming in later releases.

### Same-host daemon and harness (primary deployment)

On a bare-metal or VM host, run `kei-proxy serve` as a system service. The
harness connects to the socket at the default path
`/run/kei-proxy/runtime.sock`. Both processes run under the same OS user so the
harness can open the socket.

With systemd, provision the runtime directory and user:

```ini
# /etc/systemd/system/kei-proxy.service
[Service]
User=kei-runtime
RuntimeDirectory=kei-proxy
ExecStart=/usr/local/bin/kei-proxy serve
Environment=KEI_RUNTIME_TOKEN=kh_live_...
Environment=KEI_RUNTIME_CONTROL_PLANE_URL=https://...
```

The service manager creates `/run/kei-proxy` owned by `kei-runtime` and removes
it when the service stops. The harness process, also running as `kei-runtime`,
opens the socket directly.

### Docker same-container deployment

When the harness and runtime share a container image, run `kei-proxy serve` as a
background process (e.g., a supervisor or an init script) and have the harness
connect over the socket at the agreed path. The socket lives on the container's
own filesystem so no volume mount is needed.

For the existing OpenWebUI deployment the runtime also keeps its TCP listener on
`KEI_PROXY_LISTEN_ADDR` (default `:8085`). OpenWebUI continues to reach the
runtime at `http://connector-runtime:8085/v1` as before.

### Optional: companion container in Kubernetes

In Kubernetes you can run the runtime as a companion container in the same pod
as the harness, sharing a socket volume. This topology is optional and
functionally identical to the same-host model above.

```yaml
spec:
  securityContext:
    runAsUser: 10001
    runAsGroup: 10001
  volumes:
    - name: kei-proxy-run
      emptyDir:
        medium: Memory
  containers:
    - name: harness
      image: example/harness
      env:
        - name: KEI_RUNTIME_SOCKET_PATH
          value: /run/kei-proxy/runtime.sock
      volumeMounts:
        - name: kei-proxy-run
          mountPath: /run/kei-proxy
    - name: kei-proxy
      image: kei-connector-runtime
      args: ["serve"]
      env:
        - name: KEI_RUNTIME_TOKEN
          valueFrom:
            secretKeyRef: {name: kei-runtime, key: token}
      volumeMounts:
        - name: kei-proxy-run
          mountPath: /run/kei-proxy
```

Mount an `emptyDir` volume at `/run/kei-proxy` in both containers and run both
with the same UID (the socket is owner-only). The harness finds its runtime at
the fixed path without service discovery. For Cloud Run multi-container
services, declare an in-memory volume and mount it at `/run/kei-proxy` in the
ingress (harness) container and in the kei-proxy companion.

### Harness client example (Go)

The socket carries the same HTTP API as TCP. Configure the harness's existing
HTTP client with a Unix-socket transport and keep using the usual HTTP URL
(the hostname is ignored by the dialer):

```go
socketPath := "/run/kei-proxy/runtime.sock"
transport := &http.Transport{
    DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
        return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
    },
}
client := &http.Client{Transport: transport}
req, err := http.NewRequestWithContext(ctx, http.MethodGet,
    "http://localhost/readyz", nil)
```

Add the runtime token using the same bearer-auth mechanism as the TCP client.
Do not put the token in the URL or log it. A socket connection alone does not
replace runtime authentication or policy authorization.

### Rollout checklist

1. Deploy the runtime version that supports the socket. `serve` creates the
   socket and continues to provide the TCP listener for compatibility.
2. Make the socket directory writable by the runtime user. For a host service,
   provision `/run/kei-proxy` for that user. For a companion container in
   Kubernetes, mount a shared `emptyDir` volume at `/run/kei-proxy` in both
   containers and run them with the same UID.
3. Update the harness client to dial `KEI_RUNTIME_SOCKET_PATH` (default
   `/run/kei-proxy/runtime.sock`) and confirm `GET /readyz` succeeds through
   that client. Ensure the request still includes the runtime bearer token.
4. Keep Docker/OpenWebUI clients on `http://connector-runtime:8085/v1` during
   rollout. Once a deployment no longer needs TCP, bind it to loopback with
   `KEI_PROXY_LISTEN_ADDR=127.0.0.1:8085` and avoid publishing the port.
5. Confirm runtime logs contain `runtime_unix_listener_started` with the
   expected path and mode. A stale socket file left by a crash is replaced
   automatically. An active socket at the path (another runtime is serving),
   a regular file at the path, or a socket directory the runtime user cannot
   write is reported as `runtime_unix_listener_failed` and prevents startup.

## The TCP listener

`serve` still opens the TCP listener on `KEI_PROXY_LISTEN_ADDR` (default
`:8085`) for the existing Docker same-container OpenWebUI deployment. Harness
deployments that use the socket should not publish this port. To disable
external TCP access, bind the listener to loopback with
`KEI_PROXY_LISTEN_ADDR=127.0.0.1:8085`.
