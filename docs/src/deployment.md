# TLS and deployment

This page covers how a server listens (certificate files, a self-signed certificate or plain HTTP), what `PUBLIC_URL` decides, running behind a reverse proxy, the Host and Origin checks, containers, shutdown and running several replicas.

claude.ai connects to your server from Anthropic's infrastructure, so for claude.ai the server must be reachable from the internet at `PUBLIC_URL`, over HTTPS, with a certificate from a public certificate authority. Claude Code and other clients on your own machine can also use a certificate you trust yourself, or plain HTTP on `localhost`.

## Choosing how the server listens

The server picks one of three modes at startup, in this order:

| Settings | Mode | `Strict-Transport-Security` |
|---|---|---|
| `INSECURE_HTTP=true` | Plain HTTP. `TLS_CERT_PATH` and `TLS_KEY_PATH` are ignored. | not sent |
| `TLS_CERT_PATH` and `TLS_KEY_PATH` both set | HTTPS with the certificate and key from those files, reloaded when they change. | `max-age=31536000` |
| neither set | HTTPS with a self-signed certificate generated in memory. | not sent |

Setting only one of `TLS_CERT_PATH` and `TLS_KEY_PATH` stops startup with `TLS_CERT_PATH and TLS_KEY_PATH must be set together`. With TLS, the server speaks HTTP/1.1 and HTTP/2, chosen by ALPN.

### Certificate files

Give the server a PEM certificate chain, leaf certificate first, and its private key, as Let's Encrypt and most certificate authorities provide them:

```sh
TLS_CERT_PATH=/etc/letsencrypt/live/mcp.example.com/fullchain.pem
TLS_KEY_PATH=/etc/letsencrypt/live/mcp.example.com/privkey.pem
```

- **At startup** both files are read. If either is missing, unreadable or invalid, the server stops with `error: cannot load TLS certificate <cert> / key <key>: <reason>`. It never falls back to a self-signed certificate.
- **Renewals are picked up without a restart.** Every 30 seconds the server compares the modification times of both files. When either has changed it loads the pair again and logs `tls certificate reloaded`. New connections get the new certificate; open connections keep the one they started with.
- **A failed reload keeps the old certificate.** If the new files do not load, for example because the certificate was replaced before the key, the server logs the warning `tls certificate reload failed, keeping previous certificate` and tries again 30 seconds later.
- **Symbolic links are followed**, so certbot's `live/` directory, whose files link into `archive/`, works. Mount the whole `/etc/letsencrypt` directory into a container, not only `live/`, or the links break.
- **The files must be readable by the server's user.** certbot writes private keys readable by root only; a container running as another user needs a copy or a group it can read.

With certificate files, every response carries `Strict-Transport-Security: max-age=31536000`; see [HSTS](#hsts).

### A self-signed certificate

With neither path set, the server generates a certificate at startup for the `PUBLIC_URL` host, `localhost`, `127.0.0.1` and `::1`. It is kept in memory, never written to disk, and new on every start. The server logs it as a warning, with its SHA-256 fingerprint (shortened here):

```json
{"timestamp":"2026-10-18T14:41:33.077562Z","level":"WARN","message":"no TLS_CERT_PATH/TLS_KEY_PATH set: serving HTTPS with an in-memory self-signed certificate (not trusted by claude.ai)","addr":"0.0.0.0:8443","fingerprint_sha256":"8B:47:0E:...:0B:25","sans":"[\"mcp.example.com\", \"localhost\", \"127.0.0.1\", \"::1\"]","target":"mcp_server_core::tls"}
```

claude.ai does not trust it, and neither does any client by default. It is useful:

- for trying the server on your own machine (`curl -k`);
- to encrypt the hop from a reverse proxy or tunnel that does not verify the certificate of the server behind it. nginx does not verify upstream certificates unless you turn it on; Cloudflare Tunnel has a **No TLS Verify** setting;
- with a client you configure to pin the logged fingerprint. It changes on every restart.

### Plain HTTP

`INSECURE_HTTP=true` serves plain HTTP and logs `INSECURE_HTTP=true: serving plaintext HTTP without TLS` at startup. Use it in two cases only:

- on your own machine, with `PUBLIC_URL=http://localhost:8443`, as in the [quick start](quick-start.md);
- behind a reverse proxy or tunnel that terminates TLS, on a network you trust. `PUBLIC_URL` is then the proxy's `https://` address.

Tokens, passwords and credentials cross the hop from the proxy to the server in clear text, so the proxy and the server should share a host or a private network.

### A trusted certificate for local use

For Claude Code or other clients on your own machine, a locally trusted certificate avoids `INSECURE_HTTP`. With [mkcert](https://github.com/FiloSottile/mkcert):

```sh
mkcert -install
mkcert -cert-file cert.pem -key-file key.pem localhost 127.0.0.1 ::1
PUBLIC_URL=https://localhost:8443 TLS_CERT_PATH=$PWD/cert.pem TLS_KEY_PATH=$PWD/key.pem \
OAUTH_SIGNING_KEY=$(openssl rand -hex 32) OAUTH_ADMIN_PASSWORD='a long password' \
cargo run
```

Clients built on Node.js read extra trusted certificates from `NODE_EXTRA_CA_CERTS`, such as `NODE_EXTRA_CA_CERTS="$(mkcert -CAROOT)/rootCA.pem"`.

## HSTS

When the server serves certificate files, every response, including refusals and routes added with `Server::wrap_router`, carries:

```http
Strict-Transport-Security: max-age=31536000
```

It tells browsers to use HTTPS for the host for a year. It has no `includeSubDomains` or `preload`, so it never affects other names under your domain. With a self-signed certificate or plain HTTP the server sends no HSTS header: either the server is on your own machine, or a proxy in front holds the real certificate and sets its own policy. If your proxy should send one, add it there, as in the [nginx example](#nginx).

`server::build_app` on its own sends no HSTS header; see [Lower-level API](lower-level-api.md).

## PUBLIC_URL

`PUBLIC_URL` is the address clients use, and the server builds everything a client sees from it:

| What | Built from `PUBLIC_URL` |
|---|---|
| Each service's URL and OAuth resource | `https://mcp.example.com/<service>`, and `/mcp` |
| The OAuth issuer | `https://mcp.example.com`, in every token and in the metadata |
| The metadata documents' endpoints | `https://mcp.example.com/authorize`, `/token`, `/register` |
| The `WWW-Authenticate` challenge on 401 | `https://mcp.example.com/.well-known/oauth-protected-resource/<service>` |
| The `Host` names the MCP endpoints accept | `mcp.example.com`, besides the loopback names |
| The `Origin` always allowed | `https://mcp.example.com:443` |
| The self-signed certificate's names | `mcp.example.com`, besides the loopback names |

So it must be exactly what clients type: the same scheme, host and port. If clients use `https://mcp.example.com` through a proxy while the server is told `https://mcp.example.com:8443`, the metadata sends them to the wrong address and their tokens name the wrong resource.

It cannot have a path. The OAuth routes and metadata live at the root (`/authorize`, `/.well-known/...`), so a server cannot share a host name with something else under a sub-path such as `https://example.com/mcp-server`. Give it its own host name.

Changing `PUBLIC_URL` invalidates every token and every client registration, since each names the old issuer. Clients must remove the connector and add it again; see [What ends a grant](oauth.md#what-ends-a-grant).

## Reverse proxies and TRUSTED_PROXIES

A reverse proxy in front of the server must:

- **terminate TLS** with a publicly trusted certificate;
- **forward** to `https://<server>:8443` (the server's self-signed certificate, not verified), or to `http://<server>:8443` with `INSECURE_HTTP=true` on a network you trust;
- **keep the `Host` header** as the public host name. The MCP endpoints refuse other names with `403 Forbidden: Host header is not allowed`; see [Host and Origin checks](#host-and-origin-checks);
- **not buffer responses.** MCP answers with server-sent event streams, which must reach the client as they are written. rmcp sends a keep-alive on each event stream every 15 seconds, so an idle timeout longer than that keeps quiet streams open;
- **allow request bodies of 1 MiB**, the server's own limit;
- **pass the client's address** in `X-Forwarded-For`, and be listed in `TRUSTED_PROXIES`.

### How X-Forwarded-For is read

The server uses a client's address for one thing: the [sign-in limits](limits.md#sign-in-attempts), which count failed sign-ins, wrong static tokens and rejected credentials per address. It also appears as `ip` in the warnings those failures log. Behind a proxy every request comes from the proxy, so without `TRUSTED_PROXIES` every client shares the proxy's address, and one person's failed attempts block everyone.

With `TRUSTED_PROXIES` set:

- `X-Forwarded-For` is believed only on a connection from an address in the list. From any other address it is ignored.
- Every `X-Forwarded-For` header is read, its entries from right to left. The first entry that is not itself a trusted proxy is the client. Entries left of it, which the client could have written itself, are ignored.
- An entry may carry a port: `203.0.113.7:5000` and `[2001:db8::7]:443` are read as their addresses.
- A malformed entry met before the client's, no header at all, or a header listing only trusted proxies means the proxy's own address is used.
- IPv4-mapped IPv6 addresses (`::ffff:10.0.0.2`, as a dual-stack listener reports IPv4 peers) count as the IPv4 address, in the list, the header and the connection alike.

| Connection from | `X-Forwarded-For` | `TRUSTED_PROXIES` | Limited as |
|---|---|---|---|
| `10.0.0.2` | `198.51.100.7` | unset | `10.0.0.2` |
| `10.0.0.2` | `198.51.100.7` | `10.0.0.2` | `198.51.100.7` |
| `10.0.0.2` | `1.1.1.1, 198.51.100.7, 10.0.0.3` | `10.0.0.2,10.0.0.3` | `198.51.100.7` |
| `10.0.0.2` | `not-an-address` | `10.0.0.2` | `10.0.0.2` |
| `203.0.113.9` | `198.51.100.7` | `10.0.0.2` | `203.0.113.9` |

List only proxies you run. A client that can connect from a trusted address can choose the address it is limited as. Entries are single addresses, not ranges: a content delivery network with many edge addresses cannot be listed, and the server then limits by the edge address your own proxy reports.

### nginx

nginx terminating TLS on the same host, forwarding to the server on `127.0.0.1:8443` with its self-signed certificate:

```nginx
upstream mcp {
    server 127.0.0.1:8443;
}

# Request rate limits: per bearer token, and per address only on the sign-in page.
limit_req_zone $http_authorization zone=per_token:10m rate=20r/s;
limit_req_zone $binary_remote_addr zone=sign_in:10m rate=10r/m;

server {
    listen 443 ssl;
    server_name mcp.example.com;

    ssl_certificate     /etc/letsencrypt/live/mcp.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mcp.example.com/privkey.pem;
    add_header Strict-Transport-Security "max-age=31536000" always;

    client_max_body_size 1m;

    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header Connection "";
    proxy_buffering off;
    proxy_cache off;

    location /authorize {
        limit_req zone=sign_in burst=10;
        proxy_pass https://mcp;
    }

    location / {
        limit_req zone=per_token burst=40;
        proxy_pass https://mcp;
    }
}
```

and the server's side:

```sh
PUBLIC_URL=https://mcp.example.com
BIND_ADDR=127.0.0.1:8443
TRUSTED_PROXIES=127.0.0.1
```

- `BIND_ADDR=127.0.0.1:8443` keeps the server off the network; `--healthcheck` still reaches it.
- `proxy_pass https://mcp` encrypts the hop with the self-signed certificate. For plain HTTP, set `INSECURE_HTTP=true` and use `proxy_pass http://mcp`.
- `$proxy_add_x_forwarded_for` appends the address nginx sees to whatever the client sent, so the rightmost entry is the real client.

**About the rate limits.** The server limits sign-in guesses and upstream credential checks itself, but not the rate of requests; that is your proxy's job ([What a stateless server cannot do](security.md#what-a-stateless-server-cannot-do)). Hosted clients such as claude.ai reach the server from a few shared addresses, so do not limit `/mcp`, `/<service>`, `/token` or `/register` per client address: one busy person would block everyone. Limit per bearer token, as above, and per address only on `/authorize`, the page a person's browser opens. nginx does not count requests whose key is empty, so `/token` and `/register`, which carry no `Authorization` header, are not limited by the per-token zone. You can also add your own tower layer with [`Server::wrap_router`](https://docs.rs/mcp-server-core/latest/mcp_server_core/app/struct.Server.html#method.wrap_router).

### Tunnels

A tunnel, such as Cloudflare Tunnel, gives the server a public address with a trusted certificate without opening a port. To the server it is a reverse proxy:

- Point the tunnel at `https://<server>:8443` with certificate verification off (Cloudflare's **No TLS Verify**), or at `http://<server>:8443` with `INSECURE_HTTP=true`.
- Set `PUBLIC_URL` to the tunnel's public host name, such as `https://mcp.example.com`.
- If the tunnel's connector passes the client's address in `X-Forwarded-For`, set `TRUSTED_PROXIES` to the address the connector connects from. In Docker, give the connector a fixed address on its network so the setting stays true.

## Host and Origin checks

The MCP endpoints, `/<service>` and `/mcp`, check two headers to protect against DNS rebinding and cross-site requests from browsers. The checks come from rmcp's Streamable HTTP transport, configured by the server, and run after the bearer check: a request without a usable token gets 401 first. The OAuth routes and `/healthz` are not checked.

**`Host`** must be the `PUBLIC_URL` host, `localhost`, `127.0.0.1` or `::1`, on any port. Anything else gets `403 Forbidden: Host header is not allowed`, and rmcp logs the warning `rejected request with disallowed Host header (possible DNS rebinding attempt)`. A `Host` header that is not a valid host name gets `400 Bad Request: Invalid Host header`. Without this check, a web page could point a name it controls at your server's address and have a visitor's browser call it.

**`Origin`** is checked only when a request carries one. Browsers send it; clients that run on a server or the command line usually do not. A request with an `Origin` must come from `PUBLIC_URL`'s own origin (scheme, host and port: `https://mcp.example.com` means port 443) or match an entry of `ALLOWED_ORIGINS`. Otherwise it gets `403 Forbidden: Origin header is not allowed`, and rmcp logs `rejected request with disallowed Origin header (possible cross-origin attack)`. An `Origin` that does not parse gets `403 Forbidden: Invalid Origin header` (`Forbidden: Invalid Origin header encoding` when it is not UTF-8), and rmcp logs `rejected request with malformed Origin header`.

Add an origin to `ALLOWED_ORIGINS` when a browser-based MCP client calls the server directly, for example the MCP Inspector's page on `http://localhost:6274`. Entries take these forms:

| Entry | Matches |
|---|---|
| `https://app.example.com:443` | That origin exactly. |
| `http://localhost:*` | `http://localhost` on any port. |
| `https://app.example.com` | That host on any port, for now. rmcp logs a warning at startup for such an entry, once for each path, beginning `allowed origin without a port matches any port`: a later rmcp release will match only the scheme's default port. Write a port or `:*` instead. |
| `null` | `Origin: null`, which browsers send from sandboxed pages and `file:` URLs. |

## Body limits

The server's routes (`/healthz`, the OAuth routes and the MCP endpoints) refuse a request body larger than 1 MiB (1,048,576 bytes). A request whose `Content-Length` declares more gets `413 Payload Too Large` with the body `length limit exceeded`, before the body is read. A larger body sent without a declared length (chunked) is cut off at the limit: the OAuth endpoints then answer 413 with `Failed to buffer the request body: length limit exceeded`, and the MCP endpoints answer `500 Internal Server Error` with `Failed to read request body: length limit exceeded`. MCP messages are far smaller. Set your proxy's limit to the same size; nginx's `client_max_body_size 1m` is exactly that. See [Limits and abuse protection](limits.md) for every other limit.

Routes you add with `Server::wrap_router`, and `/favicon.ico`, are outside that limit, the request metrics and the `request` tracing span. Wrapped routes get axum's own default limit of 2 MB on extractors such as `Bytes` and `Json`. If they read bodies, add `DefaultBodyLimit::max(1_048_576)` from the re-exported `mcp_server_core::axum::extract` to them.

## Containers

The binary needs nothing but its environment: no configuration file, no writable directory apart from the audit log's, and no state to keep. A multi-stage `Dockerfile` for a server called `mcp-sea`:

```dockerfile
FROM rust:1.88-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/mcp-sea /mcp-sea
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/mcp-sea", "--healthcheck"]
ENTRYPOINT ["/mcp-sea"]
```

The `nonroot` image runs as UID 65532. The default port, 8443, needs no privileges. The build image needs Rust 1.88 or later, the crate's minimum supported version; use a newer one if your own code needs it.

### The healthcheck

`/mcp-sea --healthcheck` connects to `127.0.0.1` on the `BIND_ADDR` port, requests `GET /healthz`, and exits 0 on a `200` within 5 seconds, or prints `healthcheck failed` and exits 1. It speaks TLS unless `INSECURE_HTTP` is set, accepting any certificate since it only talks to itself. It reads `BIND_ADDR` and `INSECURE_HTTP` from the environment, which a container's `HEALTHCHECK` shares with the server.

`/healthz` shows only that the process is serving. It does not contact upstream services, so an upstream outage does not get the container restarted.

In Kubernetes, use the same command as an `exec` probe, or an `httpGet` probe on `/healthz` with `scheme: HTTPS` (the kubelet does not verify probe certificates) or `scheme: HTTP` with `INSECURE_HTTP`.

### Docker Compose

With its secrets in files, certificates from the host's certbot and a volume for the audit log:

```yaml
services:
  mcp-sea:
    image: ghcr.io/example/mcp-sea:1.0.0
    restart: unless-stopped
    ports:
      - "443:8443"
    environment:
      PUBLIC_URL: https://sea.example.com
      TLS_CERT_PATH: /etc/letsencrypt/live/sea.example.com/fullchain.pem
      TLS_KEY_PATH: /etc/letsencrypt/live/sea.example.com/privkey.pem
      OAUTH_SIGNING_KEY_FILE: /run/secrets/oauth_signing_key
      OAUTH_ADMIN_PASSWORD_FILE: /run/secrets/oauth_admin_password
      AUDIT_LOG_PATH: /audit/audit.jsonl
    secrets:
      - oauth_signing_key
      - oauth_admin_password
    volumes:
      - /etc/letsencrypt:/etc/letsencrypt:ro
      - ./audit:/audit
    read_only: true
    stop_grace_period: 15s

secrets:
  oauth_signing_key:
    file: ./secrets/oauth_signing_key
  oauth_admin_password:
    file: ./secrets/oauth_admin_password
```

- Every file the server reads, the secrets and the certificate and key, must be readable by UID 65532, and the audit directory writable by it (`sudo chown 65532:65532 audit`). If the audit file cannot be written, tool calls still work and the server logs `could not write the audit log` at most once a minute.
- `read_only: true` works: the server writes nothing else.
- `stop_grace_period` gives the server time to drain connections; see [Graceful shutdown](#graceful-shutdown).

[Configuration reference](configuration.md#a-complete-example) shows how to create the secrets.

## Graceful shutdown

On `SIGTERM` (or Ctrl-C), the server:

1. logs `shutdown signal received`;
2. stops accepting connections, ends its MCP sessions and stops watching the certificate files;
3. waits up to 10 seconds for open connections to finish;
4. exits with status 0, after flushing any traces it has not yet exported.

Give the server more than 10 seconds before your platform kills it. Docker waits 10 seconds by default, so set `stop_grace_period: 15s` (Compose) or `--stop-timeout 15` (`docker run`). Kubernetes waits 30 seconds by default.

Clients notice nothing lasting. Their tokens remain valid on the new process, since nothing is stored; their MCP session is gone, so their next request gets `404` and they open a new session.

## Replicas

Every token is a signed JWT, so any replica can verify a token another issued, and the OAuth flow works with registration, sign-in and token requests landing on different replicas. Replicas must agree on what goes into a token:

| Setting | Why it must be the same on every replica |
|---|---|
| `OAUTH_SIGNING_KEY` | Signs and verifies every token and seals every credential. |
| `PUBLIC_URL` | The issuer and the resources every token names. |
| `OAUTH_ADMIN_PASSWORD`, the sign-in mode and the verifier | Every token carries a sign-in version derived from them; a replica with another version refuses the token. |
| `<PREFIX>_SERVICES` and `<PREFIX>_COMBINED` | A replica answers 404 on a path it does not serve, and refuses to refresh a token for it. |
| `MCP_AUTH_TOKEN` | Accepted only where it is set. |

Everything else lives in each replica's memory, starts empty and is lost on restart:

| Kept per replica | Effect |
|---|---|
| Sign-in limits | Each replica counts failed attempts on its own, so with three replicas an address can make up to three times the attempts. |
| The memory of used authorization codes | A code is refused a second time by the replica that redeemed it, not by the others. Codes live 60 seconds and need the client's PKCE verifier. |
| Verdicts on credentials sent as bearer tokens, and the cap of 16 checks at once | Each replica checks a credential upstream once and caches the verdict itself. |
| MCP sessions and the session tables | A session lives on the replica that opened it. |
| The audit file | Each replica writes its own `AUDIT_LOG_PATH`. Collect the `audit` log target if you want one record. |

Because sessions are per replica, a load balancer must send every request of a session to the replica that opened it. Otherwise the request gets `404`, and the client starts a new session each time it lands elsewhere. Route on the `Mcp-Session-Id` header, which every request after `initialize` carries; requests without one can go to any replica. With nginx:

```nginx
upstream mcp {
    hash $http_mcp_session_id consistent;
    server 10.0.0.11:8443;
    server 10.0.0.12:8443;
}
```

Keep the replicas' clocks synchronised. Tokens are accepted for 5 seconds after they expire to allow for skew, and a sign-in time ahead of a replica's clock is accepted as another replica's.

## Before going live

- `PUBLIC_URL` is exactly the address clients use, and the certificate is publicly trusted.
- `OAUTH_SIGNING_KEY` is random (`openssl rand -hex 32`), kept in a file, and known to nobody else.
- `OAUTH_ADMIN_PASSWORD` is 15 characters or more; `MCP_AUTH_TOKEN` is unset or long and random.
- `TRUSTED_PROXIES` lists your proxies and nothing else.
- Requests are rate limited in front of the server, per token rather than per address.
- `METRICS_ADDR`, if set, is reachable only from your monitoring network.
- `DEBUG_UNSAFE_LOG_CONTENT` is off, and `LOG_LEVEL` does not set `debug` or `trace` for everything; see [Observability](observability.md#content-in-logs).
- The audit file's directory is writable, and the healthcheck and stop grace period are set.
- [Security model](security.md) has been read, including what a stateless server cannot do.
