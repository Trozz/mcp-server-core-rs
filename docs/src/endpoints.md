# Endpoints

This page lists every HTTP route a server built with `app::Server` serves: who may call it, what it is for and what it answers, the fields of the two metadata documents, the security headers and the 401 challenge. Every route is at the root of `PUBLIC_URL`.

## Routes

| Method | Path | Authentication | Purpose |
|---|---|---|---|
| `GET` | `/healthz` | none | Liveness check: answers `ok`. |
| `GET` | `/favicon.ico` | none | The server's icon, when [`Server::icon`](https://docs.rs/mcp-server-core/latest/mcp_server_core/app/struct.Server.html#method.icon) is set. |
| `GET` | `/.well-known/oauth-protected-resource/<service>` | none | Protected-resource metadata of one service, or of `mcp` (RFC 9728). |
| `GET` | `/.well-known/oauth-authorization-server` | none | Authorization-server metadata (RFC 8414). |
| `POST` | `/register` | none | Dynamic client registration (RFC 7591). |
| `GET` | `/authorize` | none | The sign-in page. |
| `POST` | `/authorize` | the credential, in the form | Signs the person in and redirects to the client with a code. |
| `POST` | `/token` | a code and its PKCE verifier, or a refresh token | Issues access and refresh tokens. |
| `POST`, `GET`, `DELETE` | `/<service>` | bearer token | One service's MCP endpoint (Streamable HTTP). |
| `POST`, `GET`, `DELETE` | `/mcp` | bearer token | Every service together, while `<PREFIX>_COMBINED` is `true` and at least one service is enabled. See [Several services and /mcp](combined.md). |

- A path outside these routes answers 404, for example a service that is not enabled, or `/mcp` when it is turned off. A known path called with another method answers 405.
- Routes you add with [`Server::wrap_router`](https://docs.rs/mcp-server-core/latest/mcp_server_core/app/struct.Server.html#method.wrap_router) are served as you define them, without the bearer guard, the body limit or the request metrics. Protect them yourself if they need it.
- Prometheus metrics are served on a separate listener, `METRICS_ADDR`, not on these routes; see [Observability](observability.md).
- `/healthz`, the OAuth routes and the MCP endpoints refuse a request body larger than 1 MiB: with 413 when its `Content-Length` declares more, and as [Body limits](deployment.md#body-limits) describes when it is sent without a declared length.

## The MCP endpoints

Each service is mounted at `/<service>`, and `/mcp` serves every service's tools and prompts together. The transport is rmcp's Streamable HTTP server:

| Method | Request | Answer |
|---|---|---|
| `POST` | A JSON-RPC message, with `Content-Type: application/json` and `Accept: application/json, text/event-stream`. | The response as JSON or as a server-sent event stream. The answer to `initialize` carries the new session's `Mcp-Session-Id` header, which later requests send back. |
| `GET` | `Accept: text/event-stream` and the `Mcp-Session-Id` header. | The session's stream of server-sent events. |
| `DELETE` | The `Mcp-Session-Id` header. | Ends the session: `202`. |

Sessions exist only on protocol versions before `2026-07-28`, where `initialize` starts one. rmcp serves requests that use the `2026-07-28` revision without a session: for them only `POST` applies, and `GET` and `DELETE` answer 405. When credentials are carried, every session is bound to the credential that opened it; see [MCP sessions](limits.md#mcp-sessions) for the binding and the session caps.

### Authentication

Every request needs `Authorization: Bearer <token>`; the scheme name is case-insensitive. The token is one of:

| Token | Accepted when |
|---|---|
| An access token this server issued for this path | Its grant still holds; see [OAuth and tokens](oauth.md). A token for another path is refused. |
| `MCP_AUTH_TOKEN` | It is set. See [The static token](sign-in.md#the-static-token). |
| The person's own credential | People sign in with their own credential and the verifier accepts it as a bearer token. See [Credentials sent as bearer tokens](sign-in.md#credentials-sent-as-bearer-tokens). |

A request let through carries a [`Caller`](sign-in.md#who-made-a-request) and, when credentials are carried, the person's `Credential`.

### The 401 challenge

A request without a usable token gets `401 Unauthorized` with an empty body and a `WWW-Authenticate` header that names the path's protected-resource metadata, where an MCP client starts [discovery](oauth.md#discovery):

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/weather"
```

When a token was sent and refused, the challenge adds `error="invalid_token"`:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/weather", error="invalid_token"
```

A token is refused when it is expired, issued for another path, from a grant that has ended, signed under another key, or a wrong static token or credential. The challenge never says which. [Troubleshooting](troubleshooting.md) explains how to find out.

### Responses

| Status | When |
|---|---|
| `200` | A request answered, as JSON or as an event stream. |
| `202` | A notification or response from the client accepted, or a session ended with `DELETE`. |
| `400` | A malformed MCP request, such as an unsupported `MCP-Protocol-Version` header (`Bad Request: Unsupported MCP-Protocol-Version: <version>`) or a `GET` or `DELETE` without a session id (`Bad Request: Session ID is required`). |
| `401` | No usable token: see [The 401 challenge](#the-401-challenge). |
| `403` | `Forbidden: Host header is not allowed`: the `Host` is not `PUBLIC_URL`'s host, `localhost`, `127.0.0.1` or `::1`. `Forbidden: Origin header is not allowed`: an `Origin` that is neither `PUBLIC_URL`'s nor in `ALLOWED_ORIGINS`. Both protect against DNS rebinding and cross-site requests; see [TLS and deployment](deployment.md). |
| `404` | The `Mcp-Session-Id` names a session that does not exist, has ended, or was opened with another credential (`Session not found`, or rmcp's `Not Found: Session not found`). The client starts a new session. On the `2026-07-28` revision, rmcp also answers 404 for a JSON-RPC method the server does not have. |
| `405` | Any method other than `POST`, `GET` and `DELETE`, or a `GET` or `DELETE` on the `2026-07-28` revision. |
| `406` | The `Accept` header lacks `application/json` or `text/event-stream` on a `POST`, or `text/event-stream` on a `GET`. |
| `413` | The `Content-Length` declares a body over 1 MiB (`length limit exceeded`). A longer body sent without a declared length is cut off at the limit and answered `500` (`Failed to read request body: length limit exceeded`); see [Body limits](deployment.md#body-limits). |
| `415` | A `POST` whose `Content-Type` is not `application/json`, or whose body is not JSON. |
| `422` | On a protocol version before `2026-07-28`, a `POST` without a session id that is not `initialize` (`Unexpected message, expect initialize request`). |
| `429` | Too many failed attempts from this address, with `Retry-After: 30`: `Too many attempts from this address: credentials or tokens were rejected, or several are being checked at once. Try again shortly.` |
| `503` | With `Retry-After: 30`: the person's credential could not be checked (`Your <label> could not be checked right now: <why>`), the server is refusing new addresses under heavy load, or the path holds too many sessions (`This server has too many open sessions. Try again shortly.`). |

The bearer check runs first, so a request without a usable token gets 401 whatever its `Host`. The `Host` and `Origin` checks apply to the MCP endpoints only. The limits behind 429, 503 and the session table are on [Limits and abuse protection](limits.md).

## Metadata documents

Both documents are public JSON, served with `200`.

### Protected-resource metadata

`GET /.well-known/oauth-protected-resource/<service>`, for each enabled service and for `mcp` while the combined endpoint is on:

```json
{
  "resource": "https://mcp.example.com/weather",
  "authorization_servers": ["https://mcp.example.com"],
  "bearer_methods_supported": ["header"],
  "scopes_supported": ["weather"]
}
```

| Field | Value |
|---|---|
| `resource` | `PUBLIC_URL/<service>`: the value clients send as `resource`, and the audience of its access tokens. |
| `authorization_servers` | `PUBLIC_URL`, the only authorization server. |
| `bearer_methods_supported` | `header`: tokens go in the `Authorization` header only. |
| `scopes_supported` | The service's name. |

Any other name, and `/.well-known/oauth-protected-resource` itself, answers 404.

### Authorization-server metadata

`GET /.well-known/oauth-authorization-server`:

```json
{
  "issuer": "https://mcp.example.com",
  "authorization_endpoint": "https://mcp.example.com/authorize",
  "token_endpoint": "https://mcp.example.com/token",
  "registration_endpoint": "https://mcp.example.com/register",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none"],
  "authorization_response_iss_parameter_supported": true,
  "scopes_supported": ["weather", "tides", "mcp"]
}
```

| Field | Value |
|---|---|
| `issuer` | `PUBLIC_URL`. Every token's `iss`, and the `iss` parameter on authorization responses. |
| `authorization_endpoint` | `PUBLIC_URL/authorize` |
| `token_endpoint` | `PUBLIC_URL/token` |
| `registration_endpoint` | `PUBLIC_URL/register` |
| `response_types_supported` | `code` |
| `grant_types_supported` | `authorization_code` and `refresh_token` |
| `code_challenge_methods_supported` | `S256` |
| `token_endpoint_auth_methods_supported` | `none`: public clients, without a secret. |
| `authorization_response_iss_parameter_supported` | `true` (RFC 9207). |
| `scopes_supported` | The enabled services' names, then `mcp` while the combined endpoint is on. |

There is no revocation, introspection or JWKS endpoint: tokens are signed with a shared secret (HS256) and verified only by servers that hold it. See [What statelessness means](oauth.md#what-statelessness-means).

## OAuth endpoints

How each step works, and every error message, is on [OAuth and tokens](oauth.md). In short:

| Route | Answers |
|---|---|
| `POST /register` | `201` with the client's registration as JSON. `400` with `invalid_client_metadata` or `invalid_redirect_uri` for input outside the [registration caps](oauth.md#dynamic-client-registration). |
| `GET /authorize` | `200` with the sign-in page. `400` with an error page for an unknown client or redirect URI. `302` to the redirect URI with `error` for other invalid requests. |
| `POST /authorize` | `303` to the redirect URI with `code`, `state` and `iss` on success, or with `error` for an invalid request. `400` with an error page for an unknown client or redirect URI, or when the form expired or was altered. `401` with the page again for input that is not plausible or a rejected credential. `429` or `503` when the sign-in limits refuse the address, and `503` when the credential could not be checked. See [The sign-in page](oauth.md#the-sign-in-page). |
| `POST /token` | `200` with tokens as JSON. `400` with an OAuth error as JSON. `413` for a body over the limit. See [The token endpoint](oauth.md#the-token-endpoint). |

`/register` reads JSON; `/token` and `POST /authorize` read forms (`application/x-www-form-urlencoded`).

## Health and icon

`GET /healthz` answers `200` with the body `ok`, without authentication. It shows the process is serving, nothing more: it does not contact upstream services. The binary's `--healthcheck` flag requests it on `127.0.0.1` at the `BIND_ADDR` port; see [TLS and deployment](deployment.md).

`GET /favicon.ico` answers `200` with the 128x128 PNG given to `Server::icon`, as `image/png`. Without an icon the route does not exist.

## Security headers

| Header | Value | Sent on |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` | Every response, including refusals such as 413 and routes added with `Server::wrap_router`. |
| `Strict-Transport-Security` | `max-age=31536000` | Every response, when the server serves certificate files (`TLS_CERT_PATH` and `TLS_KEY_PATH`). Not with a self-signed certificate or plain HTTP; see [TLS and deployment](deployment.md). |
| `X-Frame-Options` | `DENY` | Pages from `/authorize`. |
| `Content-Security-Policy` | `default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'` | Pages from `/authorize`. |
| `Referrer-Policy` | `no-referrer` | Pages from `/authorize`. |
| `Cache-Control` | `no-store` | Pages from `/authorize`, the redirect after a successful sign-in and every JSON answer from `/token`. |
| `Retry-After` | `30` | Every 429 and 503 this crate sends: from the bearer guard, the sign-in page and the session table. |

Why the sign-in page sends its headers is explained under [Page headers](oauth.md#page-headers). If you build the application with [`server::build_app`](https://docs.rs/mcp-server-core/latest/mcp_server_core/server/fn.build_app.html) instead of `app::Server`, it sends `nosniff` but never `Strict-Transport-Security`; see [Lower-level API](lower-level-api.md).
