# Troubleshooting

This page lists every error the server can stop with at startup, quoted as the server prints it, with its fix; then the problems that show up while it runs, such as 401, 429 and 503 answers, refused `Host` and `Origin` headers and claude.ai failing to connect; and how to investigate.

## The server does not start

### Configuration errors

The server reads its whole configuration before it starts and prints every problem it found, each on its own line starting `configuration error:`, then exits with status 1. Fix them all and start it again. A few checks only run once others pass (see [Validation](configuration.md#validation)), so a second run can show more.

In the messages below, `<PREFIX>` is the server's [prefix](configuration.md#the-prefix), `MCP` unless it sets another.

| Message | Fix |
|---|---|
| `PUBLIC_URL is required` | Set `PUBLIC_URL` to the external address clients use, such as `https://mcp.example.com`. |
| `PUBLIC_URL must be an https URL` | The value is not a URL with a host. Include the scheme: `https://mcp.example.com`, not `mcp.example.com`. |
| `PUBLIC_URL must be an https URL (http is only allowed for localhost)` | Use `https://`. `http://` is accepted only for `localhost`, `127.0.0.1` and `[::1]`. Behind a proxy that terminates TLS, `PUBLIC_URL` is still the proxy's `https://` address. |
| `PUBLIC_URL must not contain a path` | Remove the path: `https://mcp.example.com`, not `https://mcp.example.com/mcp`. The server cannot live under a sub-path; see [PUBLIC_URL](deployment.md#public_url). |
| `PUBLIC_URL must not contain a query or fragment` | Remove everything from `?` or `#`. |
| `OAUTH_SIGNING_KEY is required` | Set it, or `OAUTH_SIGNING_KEY_FILE`, to a random value: `openssl rand -hex 32`. |
| `OAUTH_SIGNING_KEY must be at least 32 bytes` | Use a longer key. `openssl rand -hex 32` gives 64 characters. |
| `OAUTH_ADMIN_PASSWORD is required` | The server signs in its owner with a password (`SignIn::OwnerPassword`, the default). Set `OAUTH_ADMIN_PASSWORD` or `OAUTH_ADMIN_PASSWORD_FILE`. |
| `OAUTH_ADMIN_PASSWORD must be at least 12 characters, not only spaces` | Choose a longer passphrase. From 15 characters the startup warning goes too. |
| `MCP_AUTH_TOKEN must not have the shape of a JWT (three dot-separated parts)` | Use a value without exactly two dots; `openssl rand -hex 32` has none. |
| `MCP_AUTH_TOKEN cannot be used when people sign in with their own <label>` | The server signs people in with their own credential, or accepts credentials sent as bearer tokens, and a static token would reach tools without one. Unset `MCP_AUTH_TOKEN`; when the verifier accepts it, a client that can send a header can send its own credential as the bearer token instead. See [The static token](sign-in.md#the-static-token). |
| `TRUSTED_PROXIES contains an invalid IP address: <entry>` | List single IP addresses, comma separated. Ranges such as `10.0.0.0/8` and host names are not accepted. |
| `BIND_ADDR has an invalid value` | Use an IP address and port, such as `0.0.0.0:8443` or `[::]:8443`. Host names such as `localhost:8443` are not accepted. |
| `METRICS_ADDR has an invalid value` | Use an IP address and port, such as `0.0.0.0:9090`. |
| `LOG_FORMAT has an invalid value` | Use `json` or `pretty`. |
| `INSECURE_HTTP must be true or false, got "<value>"` | Use `true`, `false`, `1`, `0`, `yes`, `no`, `on` or `off`. The same message names `DEBUG`, `DEBUG_UNSAFE_LOG_CONTENT`, `<PREFIX>_COMBINED` or a service's own boolean. |
| `TLS_CERT_PATH and TLS_KEY_PATH must be set together` | Set both, or neither for a self-signed certificate. See [Choosing how the server listens](deployment.md#choosing-how-the-server-listens). |
| `<NAME>_FILE: cannot read <path>: <reason>` | The file named by a `_FILE` variable is missing or unreadable by the server's user. In a container, check the mount and that the file is readable by the container's user, such as UID 65532. |
| `<NAME> is required` | A service needs this variable. Set it, or leave the service out of `<PREFIX>_SERVICES` if you do not use it. |
| `<NAME> has an invalid value` | A service's variable does not parse as the type it expects. The server's own documentation gives the format. |
| `<PREFIX>_SERVICES contains an unknown service: <name> (known: <names>)` | Use names from the list. Service names are lower case. |
| `<PREFIX>_SERVICES must name at least one service (known: <names>)` | The list has only commas or spaces. Name a service, or unset the variable to run them all. |
| `<PREFIX>_READ_ONLY contains an unknown service: <name> (known: all, <names>)` | Use registered names, or `all`. |
| `no enabled service defines how people sign in` | With `SignIn::ServiceCredential`, enable the service whose `credential_verifier` defines the sign-in, or fix the errors that stopped it from building. See [Only one service may define sign-in](sign-in.md#only-one-service-may-define-sign-in). |
| `more than one enabled service defines how people sign in (<names>): enable one of them` | Run only one of the named services on this server, with `<PREFIX>_SERVICES`. Each would hand its tools a credential meant for another upstream. |
| `the service registered as <name> is named <other>` | A programming error: the factory registered as `<name>` built a service whose `name()` returns `<other>`. Make them match. |

### Errors when the server starts serving

These come after the configuration has loaded. The server prints the error on its own line starting `error:` and exits with status 1. Once logging has started it also logs `fatal` with the error; a bad `LOG_LEVEL` or OpenTelemetry endpoint stops it before then.

| Message | Fix |
|---|---|
| `cannot load TLS certificate <cert> / key <key>: <reason>` | A file is missing, unreadable by the server's user, not PEM, or the key does not match the certificate. The server never falls back to a self-signed certificate. See [Certificate files](deployment.md#certificate-files). |
| `Address already in use (os error 98)` | Something else listens on `BIND_ADDR`, often an earlier copy of the server. Stop it or choose another port. |
| `Permission denied (os error 13)` | A port below 1024 needs privileges on most Linux systems. Listen on 8443 and map or proxy port 443 to it. |
| `Cannot assign requested address (os error 99)` | The IP address in `BIND_ADDR` is not one of this machine's. Use `0.0.0.0`, or an address the machine has. |
| `failed to create HTTP listener: <reason>` | The metrics listener could not bind `METRICS_ADDR`, for the same reasons as above. |
| `error parsing level filter: ...`, or `invalid filter directive` | `LOG_LEVEL` does not parse. Use a level, then `target=level` directives: `info,mcp_weather=debug`. See [LOG_LEVEL](observability.md#log_level). |
| `invalid exporter configuration: OTEL_EXPORTER_OTLP_ENDPOINT: invalid endpoint '<value>': <reason>` | The collector address is not a URL. Use one such as `http://otel-collector:4318`. See [Traces](observability.md#traces). |

The operating system's messages above are Linux's; other systems word them differently.

### Panics while building the server

`Server::service` panics on a name it cannot serve, before any configuration is read. These are programming errors, found the first time the binary runs:

- `service name "<name>" must be lowercase letters, digits and '-'`
- `service name "mcp" is reserved for the combined endpoint`
- `service "<name>" is registered twice`

See [Names](writing-a-service.md#names).

### Warnings at startup

The server starts, and logs a warning:

| Warning | Meaning |
|---|---|
| `OAUTH_ADMIN_PASSWORD is shorter than 15 characters: a longer passphrase is much harder to guess` | The password is accepted, but a longer one is much harder to guess. |
| `MCP_AUTH_TOKEN is shorter than 32 characters: use a long random value` | Use `openssl rand -hex 32`. |
| `INSECURE_HTTP=true: serving plaintext HTTP without TLS` | Expected behind a TLS-terminating proxy or on `localhost`; otherwise remove `INSECURE_HTTP`. |
| `no TLS_CERT_PATH/TLS_KEY_PATH set: serving HTTPS with an in-memory self-signed certificate (not trusted by claude.ai)` | Fine locally or behind a proxy that does not verify it. For claude.ai directly, set `TLS_CERT_PATH` and `TLS_KEY_PATH`. |
| `DEBUG_UNSAFE_LOG_CONTENT is enabled: message content WILL be written to logs` | Turn it off once you have what you need. |
| ``METRICS_ADDR is set but this build has no Prometheus support (feature `prometheus`): metrics are not served`` | The binary was built without the `prometheus` feature. |
| ``OTEL_EXPORTER_OTLP_ENDPOINT is set but this build has no OpenTelemetry support (feature `otel`): traces are not exported`` | The binary was built without the `otel` feature. |
| ``allowed origin without a port matches any port; a future release will match only the scheme default port. Use `:*` or an explicit port instead`` | From rmcp, once for each path, for an `ALLOWED_ORIGINS` entry without a port. Add the port, or `:*`. |

## Requests are refused

The refusals below are counted in `http_requests_total` by route and status, except a 413 for a body whose declared `Content-Length` is too large, which is refused before it is counted; see [Metrics](observability.md#metrics).

### 401 Unauthorized

A request to `/<service>` or `/mcp` without a token the path accepts gets 401 and a `WWW-Authenticate` header naming the path's metadata document. That is the normal first step of signing in: a client follows it to [discovery](oauth.md#discovery). The challenge carries `error="invalid_token"` when a token was sent and refused, and never says why.

| Cause | What to do |
|---|---|
| No `Authorization: Bearer` header. No `error` in the challenge. | The client has not signed in yet, or sends its token another way. Only the `Authorization` header is read. |
| The access token expired. They last one hour. | The client refreshes it. If refreshing fails, see [Token errors](#token-errors). |
| The token was issued for another path. | Each path is its own resource: a token for `/weather` is refused on `/tides` and `/mcp`. Sign in to the path you use; see [Each path is its own OAuth resource](combined.md#each-path-is-its-own-oauth-resource). |
| The grant has ended: 90 days since sign-in, a new owner's password, or another sign-in mode or verifier. | Sign in again. See [What ends a grant](oauth.md#what-ends-a-grant). |
| `OAUTH_SIGNING_KEY` or `PUBLIC_URL` changed. | Every token and client registration is invalid. Remove the connector and add it again. |
| A wrong static token. The server logs `wrong static token rejected` with the `ip`. | Check `MCP_AUTH_TOKEN` on both sides. The server trims spaces around the token a client sends but not around its own value, so a stray space at the end of the server's setting never matches. Wrong tokens count towards the sign-in limits. |
| A token from somewhere else on a server that signs in its owner by password, without a static token. | Nothing could accept it: the client is sending the wrong token. It is refused without counting. |
| The person's own credential, sent as the bearer token, was rejected upstream. The server logs `bearer credential rejected`. | Check the credential with the upstream service. A rejection is remembered for 60 seconds, so a key fixed upstream moments ago is refused for up to a minute. |
| A credential that cannot be one, such as one with spaces or longer than 256 bytes. | Nothing is logged and nothing is sent upstream. Check what the client sends. |

A credential found valid is trusted for 10 minutes without asking upstream again, so a key revoked upstream keeps working as a bearer token for up to 10 minutes.

To see what a token holds, decode its middle part. The server's tokens are signed, not encrypted; only a sealed credential inside is encrypted.

```sh
cut -d. -f2 <<<"$TOKEN" | python3 -c 'import base64, json, sys; p = sys.stdin.read().strip(); print(json.dumps(json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))), indent=2))'
```

Compare `iss` with `PUBLIC_URL`, `aud` with the URL of the path (`PUBLIC_URL/<service>`), `exp` with the current Unix time, and `auth_time` with 90 days ago. [Tokens](oauth.md#tokens) describes every claim.

### 403 Forbidden

The MCP endpoints check the `Host` and `Origin` headers; see [Host and Origin checks](deployment.md#host-and-origin-checks). rmcp logs each refusal as a warning.

| Body | Cause and fix |
|---|---|
| `Forbidden: Host header is not allowed` | The request named a host other than `PUBLIC_URL`'s, `localhost`, `127.0.0.1` or `::1`. Usually a proxy replaced `Host` with the upstream's name: keep it (`proxy_set_header Host $host` in nginx). Or `PUBLIC_URL` names another host than the one clients use. |
| `Forbidden: Origin header is not allowed` | A browser-based client on another origin. Add its origin, with a port or `:*`, to `ALLOWED_ORIGINS`. |
| `Forbidden: Invalid Origin header`, or `Forbidden: Invalid Origin header encoding` | The `Origin` header does not parse, or is not UTF-8. |

A `Host` header that is not a valid host name gets `400 Bad Request` with `Bad Request: Invalid Host header` instead, and rmcp logs `rejected request with malformed Host header`.

### 404 Not Found

| Where | Cause |
|---|---|
| `/<service>` | The service is not running: not in `<PREFIX>_SERVICES`, or misspelt. The `service enabled` lines at startup list what runs. |
| `/mcp` | `<PREFIX>_COMBINED=false`. |
| `/.well-known/oauth-protected-resource/<service>` | The same: no such path on this server. |
| An MCP request answered `Session not found` (or `Not Found: Session not found`) | The session named in `Mcp-Session-Id` has ended. rmcp ends a session after 5 minutes without activity; a restart ends them all; with several replicas, another replica opened it ([Replicas](deployment.md#replicas)); and a person's credential opening more than 50 sessions on one path closes its least recently used. A session opened with another credential gets the same answer. Clients open a new session, so this is only a problem if it happens on every request. |

### 429 Too Many Requests

Sign-in attempts are limited, and a refusal answers 429 with `Retry-After: 30`. On an MCP endpoint the body is `Too many attempts from this address: credentials or tokens were rejected, or several are being checked at once. Try again shortly.`; the sign-in page says `Too many attempts from this address: credentials were rejected, or several are being checked at once. Wait a little and try again.`

What counts is a failed sign-in, a wrong static token or a rejected credential sent as a bearer token, and every check still running. The limits, per minute:

| Limit | Count |
|---|---|
| Per address (IPv4 address, or IPv6 /64) | 5 attempts |
| Per block (IPv4 /24, or IPv6 /48) | 25 attempts |
| Across all addresses | 30 rejections. With a sign-in that does not carry credentials, such as the owner's password, this refuses everyone, the owner included, until the minute passes; with people's own credentials, only addresses that failed themselves. |

Clients that already hold an OAuth token are not affected: the server's own tokens never count. What to check:

- **Everyone is refused at once, behind a proxy.** Without `TRUSTED_PROXIES` every client shares the proxy's address. Set it; see [Reverse proxies](deployment.md#reverse-proxies-and-trusted_proxies).
- **Who is failing.** The warnings `oauth login failed: credential rejected`, `wrong static token rejected` and `bearer credential rejected` carry the `ip`.
- **A client retrying a wrong static token or key** in a loop locks out its own address. Fix the client's configuration, then wait a minute.

[Sign-in attempts](limits.md#sign-in-attempts) explains every limit in full.

### 503 Service Unavailable

Every 503 carries `Retry-After: 30`, and tower_http logs `response failed` at `error` for each.

| Body | Cause |
|---|---|
| `Your <label> could not be checked right now: <why>` | A person's credential could not be checked. `<why>` is the verifier's own reason (upstream down or rate limiting), `the check timed out` (15 seconds), `the server is checking too many credentials at once` (16 checks running, and no slot within 5 seconds), `too many attempts from this address; try again shortly` for a request that was waiting on the same credential's check when that check was refused by the limits, or, rarely, `the check was abandoned` or `the check stopped unexpectedly`. The server logs `bearer credential could not be checked` or `oauth login: credential could not be checked` with the reason. It does not count as a failed attempt. |
| `Your <label> could not be checked right now: the server is refusing new addresses while it is under heavy load; try again shortly` | Only when credentials are carried, as when people sign in with their own (`Ceiling::BlockFailing`). Failures have reached the overall ceiling, the server already tracks 10,000 addresses and 10,000 blocks with recent attempts, and the new address's block is not among them, so it cannot be told apart from the attack. It clears as the minute passes. The sign-in page says `This server is refusing new addresses while it is under heavy load. Try again shortly.` |
| `This server has too many open sessions. Try again shortly.` | The path holds 10,000 MCP sessions, still after entries unused for 360 seconds and sessions rmcp has ended are cleared, and none can fairly make room: with the owner's password or the static token, whenever the table is full; with people's own credentials, only for a credential that holds no session yet, when nobody else holds more than one. See [MCP sessions](limits.md#mcp-sessions). |

### 413 Payload Too Large

The body `length limit exceeded` means the request declared a body over 1 MiB. A body sent without a declared length is cut off at 1 MiB instead: the OAuth endpoints answer 413 with `Failed to buffer the request body: length limit exceeded`, and the MCP endpoints answer 500 with `Failed to read request body: length limit exceeded`. MCP messages are far smaller; check the client, or a proxy adding to the body. See [Body limits](deployment.md#body-limits).

## Sign-in fails

### On the sign-in page

| The page says | Cause |
|---|---|
| `unknown client` | The client's id was not issued by this server under its current `OAUTH_SIGNING_KEY` and `PUBLIC_URL`. Remove the connector and add it again, so it registers afresh. |
| `missing client_id`, `missing redirect_uri` | The client's request is incomplete. |
| `redirect_uri is not registered for this client` | The client asked to be sent somewhere it did not register. |
| `The login form expired or was modified. Start the connection again.` | The form is valid for 10 minutes. Start again from the client. |
| `That is not a <label>.` | The input cannot be the credential: empty, too long, or a key with spaces inside. |
| `That <label> was not accepted.`, or the verifier's own reason | Wrong password or key. It counts towards the limits. |
| `Your <label> could not be checked right now: <why>` | See [503](#503-service-unavailable). |

When the request itself is wrong, the server sends the browser back to the client with an OAuth error, which the client may show:

| Error | Description | Cause |
|---|---|---|
| `invalid_target` | `resource is required: name the URL of the service, or of /mcp for every service` | The client sent no `resource` and the server has several services. Use a client that sends `resource`; only a server with a single service can do without it. |
| `invalid_target` | `resource is not a service on this server` | The URL the client was given does not match `PUBLIC_URL` exactly, the service is not running, `/mcp` is off, or the URL has a trailing `/`. |
| `invalid_request` | `code_challenge_method must be S256`, `code_challenge is required` | The client does not use PKCE with S256. |
| `unsupported_response_type` | `response_type must be code` | The client asked for another flow. |

### Token errors

`POST /token` answers 400 with a JSON OAuth error. The common ones:

| `error` | `error_description` | Cause |
|---|---|---|
| `invalid_grant` | `sign in again` | The grant has ended; see [What ends a grant](oauth.md#what-ends-a-grant). The client should start a new sign-in. |
| `invalid_grant` | `invalid or expired refresh token` | Refresh tokens last 30 days, and none outlives its grant. Or `OAUTH_SIGNING_KEY` changed. |
| `invalid_grant` | `invalid or expired code` | Codes last 60 seconds. |
| `invalid_grant` | `code already used` | A code works once. |
| `invalid_grant` | `PKCE verification failed` | The client's verifier does not match its challenge. |
| `invalid_client` | `unknown client` | `OAUTH_SIGNING_KEY` or `PUBLIC_URL` changed since the client registered. Remove the connector and add it again. |
| `invalid_target` | `resource is not a service on this server` | The service the grant is for no longer runs. |

[The token endpoint](oauth.md#the-token-endpoint) lists every error.

## claude.ai cannot connect

Work through these from a machine outside your network:

1. **The server is reachable with a trusted certificate.** `curl https://mcp.example.com/healthz` answers `ok` without `-k`. A self-signed certificate is not trusted by claude.ai; see [TLS and deployment](deployment.md).
2. **`PUBLIC_URL` is the address you gave claude.ai.** `curl https://mcp.example.com/.well-known/oauth-protected-resource/weather` returns `"resource":"https://mcp.example.com/weather"`, exactly the URL entered in claude.ai, with the same scheme, host and port.
3. **The path answers with a challenge.** `curl -i https://mcp.example.com/weather` answers 401 with a `WWW-Authenticate` header naming the metadata document on the same host. A 404 means the service is not running there.
4. **The proxy keeps `Host` and streams responses.** A 403 `Forbidden: Host header is not allowed` in the server's log, or tool calls that hang, point at the proxy; see [Reverse proxies](deployment.md#reverse-proxies-and-trusted_proxies).
5. **Nothing in front limits per address.** claude.ai reaches the server from a few shared addresses, so a per-address rate limit at the proxy or firewall blocks it.
6. **The connector predates a change.** After `OAUTH_SIGNING_KEY` or `PUBLIC_URL` changed, remove the connector and add it again.

If the sign-in page appears but connecting still fails, follow the steps: `oauth client registered` and then `oauth authorization granted` in the log, then the metric `oauth_requests_total{endpoint="token"}` by outcome. The first step missing tells you where it stopped.

## Other problems

| Problem | Cause |
|---|---|
| Write tools are missing, or answer `read_only: the <service> service is read-only on this server` | The service is in `<PREFIX>_READ_ONLY`. A tool without `read_only_hint = true` counts as a write. See [Read-only mode and the audit log](read-only-and-audit.md). |
| Every tool appears twice | The client is connected to a service's path and to `/mcp`. Use one or the other. |
| `--healthcheck` prints `healthcheck failed` | It connects to `127.0.0.1` on the `BIND_ADDR` port within 5 seconds. Check that `BIND_ADDR` accepts loopback connections (`0.0.0.0` does, an external address does not), that `INSECURE_HTTP` is the same as the server's, and that the server has finished starting. |
| No logs at all, or no startup lines | `LOG_LEVEL` has no level for everything, such as `mcp_weather=debug` on its own. Use `info,mcp_weather=debug`. |
| Log files full of colour codes | `LOG_FORMAT=pretty` writes them even to files. Use `json`, or set `NO_COLOR=1`. |
| `could not write the audit log` | The file's directory does not exist or is not writable by the server's user. Tool calls still work, and the audit lines are still logged on the `audit` target. See [When the file cannot be written](read-only-and-audit.md#when-the-file-cannot-be-written). |
| `tls certificate reload failed, keeping previous certificate` | The renewed files do not load yet, often the certificate written before its key. The server tries again every 30 seconds and keeps serving the old certificate meanwhile. |

## Investigating

- **Read the warnings first.** Refusals log a warning with the address (`ip`) or the reason, and the startup lines say what runs where.
- **See every request.** `LOG_LEVEL=info,tower_http=debug` logs each request's start and finish with its status and latency, without content.
- **Raise your own crates** with `DEBUG=true`. Avoid `LOG_LEVEL=debug` for everything on a server people use: rmcp then logs tool arguments and results. See [Content in logs](observability.md#content-in-logs).
- **Watch the counters.** `http_requests_total` by route and status shows where requests fail; see [Metrics](observability.md#metrics).
- **Check by hand.** [Checking a connection by hand](connecting-clients.md#checking-a-connection-by-hand) opens an MCP session with curl.

When you report a bug, include the server's version (`--version`), the version of mcp-server-core, and the log lines around the problem. The logs contain no secrets, but check them for IP addresses and, if `DEBUG_UNSAFE_LOG_CONTENT` was on or `LOG_LEVEL` set `debug` or `trace` for everything, for content. Report security problems privately, as [Reporting a vulnerability](security.md#reporting-a-vulnerability) describes, not in a public issue.
