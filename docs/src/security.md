# Security model

mcp-server-core is meant to be exposed to the internet, in front of tools that act on someone's behalf. This page sets out what it defends against and how, what a server that stores nothing cannot do, what remains your responsibility, and how to report a vulnerability. The numbers behind the defences are on [Limits and abuse protection](limits.md).

## What is at stake

| Secret | Held by | What it gives whoever has it |
|---|---|---|
| `OAUTH_SIGNING_KEY` | The server | Any token for any path, and the contents of every sealed credential. |
| `OAUTH_ADMIN_PASSWORD` | The owner | Sign-in to every service, on a server where the owner signs in. |
| `MCP_AUTH_TOKEN` | The owner's clients | Every service path, without OAuth. |
| A person's upstream credential, such as an API key | That person, and sealed inside their tokens | Their account with the upstream service, through your tools or directly. |
| An access token | An MCP client | One path, for up to an hour. |
| A refresh token | An MCP client | New access tokens for one path, for up to 30 days at a time and no more than 90 days after sign-in. |

The server's job is to let through only requests that carry one of these legitimately, to keep the long-lived secrets out of reach, and to make guessing a password, token or key too slow to pay off.

## Threat model

The server defends against the following.

### Unauthenticated access

Every service path, `/mcp` included, requires one of:

- an OAuth access token issued for that path, whose audience is the path's own resource URL (RFC 8707), so a token for `/weather` is refused on `/tides`;
- the static token, `MCP_AUTH_TOKEN`, when one is set;
- a credential the verifier accepts, sent directly as the bearer token, when the verifier accepts bearer credentials (by default, whenever people sign in with their own credentials).

Anything else gets 401 with a `WWW-Authenticate` header that names the path's metadata, adds `error="invalid_token"` when a token was sent, and never says why the token was refused; see [The 401 challenge](endpoints.md#the-401-challenge). Access tokens are checked for their signature (HS256 under `OAUTH_SIGNING_KEY`), issuer, audience, kind and expiry, with 5 seconds of leeway, and for a grant that still holds. A token of one kind, such as a refresh token or a client registration, is never accepted as another.

The routes open without a token, `/healthz`, the metadata documents, `/register`, `/authorize`, `/token` and `/favicon.ico` (when the server has an icon), give no access to tools; [Endpoints](endpoints.md) lists them. Routes you add with `Server::wrap_router` are outside the bearer guard, so protect them yourself.

### Guessing

Everything a person can guess at is counted:

- Failed sign-ins on the sign-in page, rejected bearer credentials and wrong static tokens count towards a per-address limit (5 a minute; IPv6 by /64) and a per-block limit (25 a minute per IPv4 /24 or IPv6 /48), from the moment a check starts, so concurrent guesses gain nothing.
- A blocked address cannot sign in or use the static token, even correctly, until the limit clears.
- Failures across all addresses are capped at 30 a minute too. When the credential is not carried, as with one shared secret (the owner's password, and the static token beside it), reaching that cap blocks everyone, the owner included, while the attack lasts, so a botnet gains nothing from more addresses; clients that already hold an OAuth token keep working. When credentials are carried, as with per-person credentials, the cap blocks only addresses that have failed themselves, so an attacker cannot lock out people on other networks. People sharing the attacker's /24 or /48 can be held up by its block limit. The mode follows the verifier's `carried()` alone.
- This server's own tokens, even expired, never count. When the verifier does not accept bearer credentials and no static token is set, as on an owner's-password server without `MCP_AUTH_TOKEN`, other bearer tokens could not be a guess at anything and are refused without counting. When it does accept them (by default, whenever credentials are carried), any other token of a plausible shape is checked as a credential, and a rejection counts.

Secrets are compared in constant time: the owner's password, the static token, the sign-in form's binding, the sign-in version in tokens and the PKCE challenge are compared through their SHA-256 digests, so neither their content nor their length leaks through timing. Weak secrets are refused or flagged at startup:

- `OAUTH_SIGNING_KEY` must be at least 32 bytes.
- `OAUTH_ADMIN_PASSWORD` must be at least 12 characters and not only spaces, and gets a warning below 15.
- `MCP_AUTH_TOKEN` gets a warning below 32 characters. It is refused when shaped like a JWT (three dot-separated parts), and next to a verifier that carries credentials or accepts them as bearer tokens.

[Sign-in attempts](limits.md#sign-in-attempts) lists exactly what counts, and [The global ceiling](limits.md#the-global-ceiling) the two modes.

### Abusing the upstream service through the server

When people sign in with their own credentials, each check is a request to the upstream service, and the server must not become a way to flood it:

- Credentials of an implausible shape are refused locally, without a check.
- At most 16 checks run at once, a check waits at most 5 seconds for a free slot, each is timed out after 15 seconds, and concurrent requests presenting the same credential share one check.
- Verdicts on bearer credentials are cached under the credential's SHA-256: a valid one for 10 minutes, a rejected one for 60 seconds.
- Checks count towards the per-address and per-block limits from the moment they start, so one network can make at most 25 rejected checks a minute.

There is deliberately no global cap on new checks: anyone with enough networks could use one up to keep everyone else from signing in. An attacker with many networks can therefore still have the server send many junk credentials upstream; limit that at the network if it matters. A credential found valid in the last ten minutes is let in even from a blocked address: its holder has already proved possession, and blocking it would only hurt people behind a shared address. [Credential checks](limits.md#credential-checks) and [Verdict cache](limits.md#verdict-cache) have the details.

### Grants outliving the sign-in

Every code, access and refresh token carries a keyed hash of how people sign in (`ver`: the sign-in mode, the verifier's label and its generation) and when this person signed in (`auth_time`). So:

- changing the owner's password, switching sign-in mode, or changing the verifier's label or generation ends every earlier grant;
- every grant ends 90 days after sign-in however often it is refreshed, and neither its access nor its refresh token outlives it;
- a token minted for one sign-in mode or upstream service is refused by a server using another, even with the same key and URL, so a sealed credential never reaches the wrong upstream.

For the owner's password, the generation is a hash of the password, and `ver` is a keyed hash of that under `OAUTH_SIGNING_KEY`, so a token reveals nothing usable about the password. [What ends a grant](oauth.md#what-ends-a-grant) lists every event and its effect.

### Authorization code interception and CSRF

- PKCE with S256 is required; `plain` and requests without a challenge are refused.
- Codes are one-time and last 60 seconds.
- The sign-in form is bound to its exact request: a form token, valid for 10 minutes, carries a hash of the client, redirect URI, PKCE challenge, `state`, scope and resource, and a form whose fields were changed is refused.
- Redirect URIs must be registered by the client and match exactly, must be `https` (or `http` on a loopback host, for native apps), carry no fragment or user information, and are capped at 10 per client and 2,048 bytes each. An unknown client or an unregistered redirect URI gets an error page, never a redirect.
- Responses to the client carry `iss` (RFC 9207), so a client talking to several authorization servers can tell which one answered.
- A successful sign-in answers `303 See Other`, so no browser re-sends the form, and with it the password, to the client's redirect URI.

[The sign-in page](oauth.md#the-sign-in-page) and [PKCE](oauth.md#pkce) describe the flow.

### Clickjacking and leaks from the sign-in page

The sign-in page is the one page a person's browser opens, and the one place they type a secret. It:

- sends `X-Frame-Options: DENY` and a strict `Content-Security-Policy` (`default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'`), so it cannot be framed and runs no script;
- sends `Cache-Control: no-store` and `Referrer-Policy: no-referrer`, so neither the page nor its URL is kept or passed on;
- escapes every value it shows;
- shows the host the person will be sent to after signing in;
- shows the client's name, capped at 200 characters and free of control characters, marked as self-reported and unverified.

Every response from `app::Server` sends `X-Content-Type-Options: nosniff`, and `Strict-Transport-Security: max-age=31536000` when it serves certificate files (`TLS_CERT_PATH`). With a self-signed certificate or plain HTTP, the proxy in front sets its own policy. `server::build_app` on its own sends `nosniff` only. [Security headers](endpoints.md#security-headers) lists every header.

### DNS rebinding and cross-site requests

The MCP endpoints check `Host` and `Origin`, so a web page cannot use a person's browser to reach a server on their machine or network:

- `Host` must be the host of `PUBLIC_URL`, `localhost`, `127.0.0.1` or `::1`, on any port. Anything else gets 403 with the body `Forbidden: Host header is not allowed`.
- An `Origin`, when one is sent, must be the origin of `PUBLIC_URL` or one listed in `ALLOWED_ORIGINS`. Anything else gets 403 with the body `Forbidden: Origin header is not allowed`. Requests without an `Origin`, as from hosted and command-line clients, pass.

Behind a reverse proxy, pass the original `Host` on. [Host and Origin checks](deployment.md#host-and-origin-checks) covers proxies and `ALLOWED_ORIGINS`.

### One person reaching another's session

When credentials are carried, as when people sign in with their own credentials, MCP sessions are bound to the credential that opened them, by its SHA-256: a session id is useless with any other credential, and a request that names someone else's session gets the same `404 Session not found` as one for a session that does not exist. Nobody can read from or end another person's session, even knowing its id.

One credential holds at most 50 sessions on a path, and opening more replaces its own oldest. When a path's session table is full, a newcomer takes a slot from whoever holds the most, so nobody is pushed out by someone holding fewer. [MCP sessions](limits.md#mcp-sessions) has the rules.

Without carried credentials, as with the owner's password or the static token, every session on a path has the same owner. On a server where only the owner signs in there is one person, so nothing is lost. A custom verifier whose `carried()` is `false` but which lets several people sign in gets no separation between their sessions: anyone signed in who learns a session id can use it.

### Credential exposure

- **Upstream credentials are never stored.** A person's credential is checked once, then sealed into their tokens with ChaCha20-Poly1305, under a key derived from `OAUTH_SIGNING_KEY` with HKDF-SHA256 and a fresh random nonce each time. It is opened again on every request, and a sealed credential that has been altered does not open. [Sealed credentials](sign-in.md#sealed-credentials) describes the format.
- **They never reach the logs.** Credentials are never logged, the `Credential` type prints as `Credential(..)` in `Debug` output, configuration errors never contain secret values, and caches and session tables key credentials by their SHA-256, never the credential.
- **People are named without revealing their credential.** Logs and the audit log name people by a subject such as `key:` and 16 hex digits of an HMAC-SHA256 of the credential under a key derived from `OAUTH_SIGNING_KEY`, never the credential, so a subject seen in a token or log line cannot be used to guess the credential offline. See [Subjects](sign-in.md#subjects).
- **Session ids stay out of logs.** rmcp's targets that log MCP session ids are capped at `warn` whatever `LOG_LEVEL` says.

The crate never logs what people read or write through tools. Services should log such content only when `observability::content_logging_enabled()` says the operator set `DEBUG_UNSAFE_LOG_CONTENT`; [Observability](observability.md) lists what is never logged.

## What a stateless server cannot do

Nothing is stored, so restarts and replicas need only the configuration: there is no database or volume to protect, back up or keep in step. The price:

- **No refresh-token reuse detection.** OAuth 2.1 asks an authorization server to notice when an old refresh token is used again and revoke the grant; that needs a record of every grant. A stolen refresh token works until it expires, the grant reaches its 90 days, the owner's password changes or `OAUTH_SIGNING_KEY` is rotated.
- **No revoking one person or one client.** Revocation is all or nothing: rotate `OAUTH_SIGNING_KEY` (everyone signs in again, and clients register again) or, with the owner's password, change the password (everyone signs in again). With per-person credentials, revoking a key at the upstream service also stops it working through the server, since the upstream service refuses it.
- **Limits are per replica.** Each replica keeps its own sign-in limits, one-time-code memory, verdict cache and MCP session tables. Behind several replicas an address gets its allowance on each, and a code could be exchanged once on each within its 60 seconds; the exchange still needs the PKCE verifier, which only the client has. [Replicas](deployment.md#replicas) covers running several.
- **No request rate limiting.** Limit request rates at your reverse proxy or with a tower layer added through `Server::wrap_router`. Do not limit `/mcp`, `/<service>`, `/token` or `/register` per client address if hosted clients such as claude.ai use the server: they reach it from a few shared addresses, so one busy person would block everyone.

For single sign-on, MFA or many named users, put an identity-aware gateway (Cloudflare Access, oauth2-proxy and the like) in front of `/authorize`; that is the only page a person's browser opens. [What statelessness means](oauth.md#what-statelessness-means) explains the trade-off from the OAuth side.

## Out of scope: your responsibilities

The server cannot do these for you:

- **Keep `OAUTH_SIGNING_KEY` secret.** Whoever has it can mint tokens and open every sealed credential. Generate it at random and give it to the server as a secret file rather than a plain variable:

  ```sh
  openssl rand -hex 32 > /run/secrets/oauth_signing_key
  export OAUTH_SIGNING_KEY_FILE=/run/secrets/oauth_signing_key
  ```

  Rotating it is also how you revoke everything at once.
- **Serve over TLS.** Use certificate files, or a proxy in front that terminates TLS. Set `TRUSTED_PROXIES` only to proxies you run; otherwise clients can choose the address they are rate limited as. [TLS and deployment](deployment.md) covers both.
- **Choose strong secrets.** Use a passphrase for `OAUTH_ADMIN_PASSWORD` (the server warns below 15 characters) and a long random `MCP_AUTH_TOKEN` (it warns below 32), or leave `MCP_AUTH_TOKEN` unset if every client can use OAuth.
- **Mark your tools.** What your tools do with the access they are given is up to you. Mark tools that only read with `read_only_hint = true`, so read-only mode and the audit log treat the rest as writes; then start cautious services read-only. See [Read-only mode and the audit log](read-only-and-audit.md).
- **Limit request rates** in front of the server, as described above.
- **Keep the metrics listener private.** `METRICS_ADDR` serves plain HTTP without authentication; bind it to an internal network.
- **Never debug with content in production.** `DEBUG_UNSAFE_LOG_CONTENT` turns on debug logs and lets services write what people read and write into the logs; the server warns at startup while it is set.
- **Treat logs as personal data.** Warnings about rejected attempts record the client's address, and the audit log records who changed what and when. Keep the audit file (created with mode `0600`) and your logs accordingly.
- **Keep the crate up to date.** Until 1.0 only the latest minor version receives security fixes; see [Releases and versioning](releases.md).

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: on the [repository's Security tab](https://github.com/Trozz/mcp-server-core-rs/security), choose **Report a vulnerability**. Do not open a public issue.

You should get a reply within a week. Fixes are released as patch versions and announced in a GitHub security advisory once a fixed version is available. Only the latest minor version receives security fixes until 1.0.

The policy is also in the repository as [SECURITY.md](https://github.com/Trozz/mcp-server-core-rs/blob/main/SECURITY.md).
