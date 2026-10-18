# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) (before 1.0, a minor version may change
the API).

## [Unreleased]

### Added

- A documentation site, <https://trozz.github.io/mcp-server-core-rs/>, built with mdBook from
  `docs/` and published from `main`. Its Rust examples are compiled as doctests.

## [0.1.0] - 2026-10-18

The first release, extracted from the servers behind
[mcp-icloud](https://github.com/Trozz/mcp-icloud) and mcp-companies-house, which each carried a
copy of this code.

### Added

- `app::Server`: a whole MCP server binary from a list of services, with `--version`, `--help`
  and `--healthcheck`, service selection (`<PREFIX>_SERVICES`), the combined `/mcp` endpoint
  (`<PREFIX>_COMBINED`), read-only services (`<PREFIX>_READ_ONLY`) and the audit log
  (`AUDIT_LOG_PATH`).
- `app::SignIn`: sign in with the owner's password (`OAUTH_ADMIN_PASSWORD`, optionally
  `MCP_AUTH_TOKEN`), with each person's own credential for the upstream service, or with your own
  `CredentialVerifier`.
- An OAuth 2.1 authorization server with dynamic client registration, PKCE (S256), resource
  indicators and protected-resource metadata, every service its own protected resource.
- Per-person credentials sealed into tokens (ChaCha20-Poly1305 under a key derived from
  `OAUTH_SIGNING_KEY`), or sent directly as bearer tokens with cached verdicts.
- Abuse limits: per-address (IPv6 by /64) and global sign-in limits, shared and capped credential
  checks, MCP sessions bound to the credential that opened them and capped per credential.
- A read-only rule and write audit log for every service, from tools' `read_only_hint`.
- TLS from files with hot reload, self-signed certificates or plain HTTP; graceful shutdown;
  JSON logs; Prometheus metrics (feature `prometheus`); OpenTelemetry traces (feature `otel`).
- Configuration from environment variables with `_FILE` variants and every error reported at once.
- `Service::router` now has a default that serves `Service::handler`, so a service implements
  just `name` and `handler`.
- MCP prompts: each service's prompts are offered on `/mcp` as `<service>_<prompt>`, and
  `prompt::tool_prefix` lets a prompt name tools as the endpoint calls them (from mcp-icloud).

- `caller::Caller` on every authenticated request (who signed in and how), recorded in the audit
  log as `subject`, and `Server::wrap_router` to add your own layers.
- Tokens carry who signed in (`sub`), a keyed sign-in version (`ver`, from the sign-in mode, the
  verifier's label and its `generation`) and the sign-in time (`auth_time`): changing the owner's
  password, the sign-in mode or the verifier ends every earlier grant, and a grant ends 90 days
  after sign-in however often it is refreshed; neither its access nor its refresh token outlives
  it. A person signing in with their own credential is named `key:` and a short hash keyed by
  `OAUTH_SIGNING_KEY` (`AuthState::subject_of`; a verifier can name them itself).
- Authorization responses carry `iss` (RFC 9207). Client registration is capped (10 redirect URIs
  of up to 2048 bytes, a client name of up to 200 characters). Malformed `/token` and `/register`
  requests get OAuth JSON errors (400). Every response sends `X-Content-Type-Options: nosniff`,
  and HSTS when the server serves certificate files.
- A limit per wider block (IPv4 /24, IPv6 /48) of 25 attempts a minute next to the per-address
  one, so one allocation cannot spread guesses over thousands of addresses. Attempts still being
  checked count towards both, never towards the global ceiling. When 10,000 addresses are tracked,
  a new one is judged by its block, and refused as busy (503) only when blocks cannot be tracked
  either (from mcp-companies-house).
- Fair session shares: when a path's session table is full, idle and ended sessions are cleared
  first, then a newcomer takes a slot from whoever holds the most, so a few hundred credentials
  cannot lock everyone out. A refusal is decided before rmcp builds the session (from
  mcp-companies-house).
- Prompts on `/mcp` that name a service's tools get those names prefixed automatically, as well as
  through `prompt::tool_prefix` (from mcp-companies-house).

### Changed, compared with the copies in the two servers

- Tokens issued before this version lack the new claims, so everyone signs in once more after
  upgrading.
- On an owner's-password server without a static token, bearer tokens that are not this server's
  are refused without counting towards the sign-in limits, so they cannot lock the owner out. A
  static token is refused at startup next to a verifier that takes bearer credentials, or when
  shaped like a JWT, reported with every other configuration error.
- A credential that has the shape of a JWT but was not issued here is checked as a credential;
  this server's own tokens, even expired, are never sent upstream.
- More than one enabled service defining how people sign in is a startup error, as is an owner's
  password of only spaces. A short password or static token is warned about.
- `X-Forwarded-For` entries with a port are understood, and IPv4-mapped IPv6 addresses
  (`::ffff:10.0.0.1`, as a dual-stack listener reports IPv4 peers) match `TRUSTED_PROXIES` and
  share limits with the IPv4 address.
- Log caps (`Service::log_caps`) never raise a target above `LOG_LEVEL`, and the audit target stays
  on at `info` whatever the level.
- `SignIn`, `CredentialCheck`, `Ceiling`, `TlsMode`, `TokenKind`, `JwtError`, `SealError` and
  `app::Loaded` are `#[non_exhaustive]`, so later versions can add to them.

- Wrong static tokens count towards the sign-in limits, and a blocked address cannot use the
  static token until the limit clears, so `MCP_AUTH_TOKEN` cannot be guessed. This server's own
  tokens, even expired, never count.
- The global sign-in ceiling depends on how people sign in: with the owner's password it blocks
  everyone (as mcp-icloud did); with per-person credentials only addresses that failed themselves
  (as mcp-companies-house did). See `guards::Ceiling`.
- Successful sign-in answers `303 See Other` (RFC 9700), not `302 Found`.
- The owner's password is compared exactly as typed; credentials for upstream services are trimmed.
- Random token ids no longer need the `uuid` crate.

### Planned

- Client ID Metadata Documents, which the MCP authorization spec now prefers to dynamic client
  registration.

[0.1.0]: https://github.com/Trozz/mcp-server-core-rs/releases/tag/v0.1.0
