# Why kei-proxy serves over a Unix socket

`kei-proxy serve` exposes its HTTP/1.1 API on a Unix domain socket, by default
`/run/kei-proxy/runtime.sock` (override with `KEI_RUNTIME_SOCKET_PATH`). The
runtime creates the socket with mode `0600`, refuses to replace an active
socket or a regular file, replaces a stale socket left behind by a crash, and
removes the socket on graceful shutdown. Requests over the socket still go
through bearer authentication and model authorization. The socket changes how
the harness reaches the proxy, not what the harness is allowed to do.

There are three reasons for this design.

## 1. Speed

A harness calls kei-proxy before every governed tool call, so each call's
latency adds up over an agent run. Traffic on a Unix socket stays inside the
kernel. There is no TCP handshake, no loopback routing, no TLS negotiation,
and no Nagle or congestion-control behavior. Each request costs one local IPC
round trip.

## 2. Simplicity

The address is just a file path, so there is no port to choose, reserve,
or collide on. The protocol is still plain HTTP/1.1, so harnesses can use any
ordinary HTTP client with a Unix-socket dialer, for example
`curl --unix-socket /run/kei-proxy/runtime.sock http://localhost/readyz`.
Nothing new needs to be framed or versioned. Startup and shutdown are also
simple: the socket appears when the runtime is ready to accept connections
and disappears when it stops.

## 3. kei-proxy is a sidecar

kei-proxy is built as a sidecar. It runs next to one harness in the same pod,
Cloud Run service, or host, and shares that harness's lifecycle. A Unix socket
on a shared volume fits this model:

- **Nothing is exposed on the network.** Because the socket lives on a volume
  shared by the two processes, there is no listening port to secure, no TLS
  certificate to issue or rotate, and no network policy to write.
- **Access control comes from the filesystem.** The mode (`0600`) and owner of
  the socket path decide who can connect. Only processes running as the
  runtime's OS user can open it.
- **There is one proxy per harness and no service discovery.** The harness
  finds its proxy at a fixed path. There is no registry, DNS name, or load
  balancer, and a proxy can't be shared or reached by another tenant's
  harness.

### Shared-volume setup

Mount the same volume at `/run/kei-proxy` in both the harness and kei-proxy,
and run both as the same UID, because the socket is owner-only.

Kubernetes, using an `emptyDir` shared by the two containers in a pod:

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

For a Cloud Run multi-container service, declare an in-memory volume and mount
it at `/run/kei-proxy` in the ingress (harness) container and in the
kei-proxy sidecar.

On a bare-metal or VM host, run kei-proxy as a service under the harness's
user and have the service manager create the directory. With systemd, for
example, use `User=<harness user>` and `RuntimeDirectory=kei-proxy`, which
creates `/run/kei-proxy` owned by that user and removes it when the service
stops.

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
2. Make the socket directory writable by the runtime user. For a sidecar,
   mount one shared volume at `/run/kei-proxy` in both containers and run them
   with the same UID. For a host service, provision the runtime directory.
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
`:8085`) for the existing Docker same-container OpenWebUI deployment. Sidecar
deployments should connect through the socket and should not publish that
port.
