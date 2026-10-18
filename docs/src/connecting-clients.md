# Connecting clients

This page shows how to add a server to claude.ai, Claude Desktop, Claude mobile, Claude Code and other MCP clients, and which URL to give each. The examples use a server at `https://mcp.example.com` with two services, `weather` and `tides`.

## Which URL to use

Each service is a separate MCP server at its own path, and `/mcp` offers every service together:

| URL | What the client gets |
|---|---|
| `https://mcp.example.com/weather` | The `weather` service's tools and prompts under their own names, and its resources if it [serves them](writing-a-service.md#overriding-the-router). |
| `https://mcp.example.com/tides` | The `tides` service, likewise. |
| `https://mcp.example.com/mcp` | Every service's tools and prompts in one connector, named `<service>_<name>`, such as `weather_forecast`. |

- **Each URL is its own sign-in.** A token issued for `/weather` is refused on `/tides` and on `/mcp`; see [Resource indicators and audiences](oauth.md#resource-indicators-and-audiences). A per-service connector is the narrower grant.
- **Use per-service URLs or `/mcp`, not both.** With both, every tool appears twice.
- **Read-only rules are the same on both.** A service made read-only with `<PREFIX>_READ_ONLY` is read-only on its own path and under `/mcp`; see [Read-only mode and the audit log](read-only-and-audit.md).
- **Resources are served on each service's own path only.** Connect to the service's URL if you need them.
- **`/mcp` can be turned off** with `<PREFIX>_COMBINED=false`; it then answers 404. See [Several services and /mcp](combined.md).

At startup the server logs a `service enabled` line with the URL of each service, and `combined endpoint enabled` with the URL of `/mcp`.

## claude.ai, Claude Desktop and Claude mobile

claude.ai connects from Anthropic's servers, not from your computer. The server must be reachable from the internet at `PUBLIC_URL`, with a certificate from a public certificate authority. A self-signed certificate or a `localhost` URL does not work; see [TLS and deployment](deployment.md).

1. In claude.ai, open **Settings**, then **Connectors**, then **Add custom connector**.
2. Enter the URL, for example `https://mcp.example.com/weather`, or `https://mcp.example.com/mcp` for every service.
3. claude.ai registers itself with the server and opens the sign-in page. The page names the service, or "every service on this server, through `/mcp`", and the host you will be sent back to, `claude.ai`.
4. Enter what the page asks for: the owner's password, or your own key for the upstream service.

The connector then works on its own. Its access token lasts an hour, and it refreshes it without asking you. It asks you to connect again:

- 90 days after you signed in;
- when it has not refreshed for 30 days, so its refresh token has expired;
- when the owner's password, or the way people sign in, changes.

When `OAUTH_SIGNING_KEY` or `PUBLIC_URL` changes, the connector's registration stops working too: remove the connector and add it again. [What ends a grant](oauth.md#what-ends-a-grant) has the full list.

Connectors added in claude.ai are also available in Claude Desktop and the Claude mobile apps.

## Claude Code

Claude Code runs on your computer, so it can also reach a server on your network or on `localhost`. It can sign in with OAuth or send a header.

### Signing in with OAuth

```sh
claude mcp add --transport http weather https://mcp.example.com/weather
```

Then run `/mcp` inside Claude Code, choose the server and authenticate. Your browser opens the server's sign-in page. Claude Code registers a redirect URI on `localhost`, which the server accepts for native apps.

### With the static token

On a server that uses the owner's password and sets `MCP_AUTH_TOKEN`, skip OAuth by sending the token as a header:

```sh
claude mcp add --transport http sea https://mcp.example.com/mcp \
  --header "Authorization: Bearer $MCP_AUTH_TOKEN"
```

The static token is accepted on every service path and on `/mcp`, so the same header works for `https://mcp.example.com/weather`. See [The static token](sign-in.md#the-static-token) for its rules.

### With your own key

On a server where each person signs in with their own credential, send yours directly, if the server accepts credentials as bearer tokens (the default):

```sh
claude mcp add --transport http example https://mcp.example.com/example \
  --header "Authorization: Bearer $EXAMPLE_API_KEY"
```

The server checks the key upstream the first time and remembers the verdict briefly. See [Credentials sent as bearer tokens](sign-in.md#credentials-sent-as-bearer-tokens).

Claude Code stores the header with the server's configuration. Avoid `--scope project` for a header that holds a secret: that scope writes it to `.mcp.json` in the project, which is often committed.

## Other MCP clients

Any client that speaks the MCP Streamable HTTP transport works, in one of two ways:

- **OAuth.** The client follows the MCP authorization specification: it reads the `WWW-Authenticate` header of the first 401, fetches the metadata, registers itself, and signs in with the authorization code grant and PKCE (S256). It must send `resource` with the URL it connects to when the server has more than one service, and register an `https` redirect URI or an `http` one on `localhost`, `127.0.0.1` or `[::1]`. [OAuth and tokens](oauth.md) describes every step.
- **A bearer header.** The client sends `Authorization: Bearer` with the static token, or with the person's own credential where the server accepts it.

To try a server interactively, run the [MCP Inspector](https://github.com/modelcontextprotocol/inspector) with `npx @modelcontextprotocol/inspector`, choose the Streamable HTTP transport, enter the URL, and either sign in with OAuth or add an `Authorization` header.

### Checking a connection by hand

An `initialize` request with `curl` shows whether the token, the host and the service work, without a client in the way:

```sh
curl -si https://mcp.example.com/weather \
  -H "Authorization: Bearer $MCP_AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'
```

A `200` with an `Mcp-Session-Id` header and the `initialize` result means everything works. Other answers point to the cause:

| Response | Meaning |
|---|---|
| `401` with `WWW-Authenticate` | No token, or one this path does not accept. With `error="invalid_token"`, a token was sent and refused. See [Endpoints](endpoints.md#the-401-challenge). |
| `403 Forbidden: Host header is not allowed` | The request reached the server under another host name than `PUBLIC_URL`'s, often because a proxy rewrote `Host`. See [Host and Origin checks](deployment.md#host-and-origin-checks). |
| `403 Forbidden: Origin header is not allowed` | A browser-based client on another origin. Add it to `ALLOWED_ORIGINS`; see [Configuration reference](configuration.md). |
| `404` | No such path: a service that is not enabled, or `/mcp` turned off. |
| `406` or `415` | The `Accept` or `Content-Type` header is missing or wrong. |
| `429` or `503` with `Retry-After` | Refused by the sign-in limits after wrong static tokens or credentials from this address, a credential that could not be checked upstream, or too many open sessions. See [Limits and abuse protection](limits.md). |

[Troubleshooting](troubleshooting.md) covers these and the problems a client reports in its own words.

## Trying it locally

Claude Code and the MCP Inspector can connect to a server on your own computer, with `PUBLIC_URL=http://localhost:8443` and `INSECURE_HTTP=true`. [Quick start](quick-start.md) has the exact commands. claude.ai cannot reach `localhost`.

Next: [Configuration reference](configuration.md), to run a server of your own.
