# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) (before 1.0, a minor version may change
the API).

## [0.1.0] - unreleased

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

### Changed, compared with the copies in the two servers

- Wrong static tokens count towards the sign-in limits, and a blocked address cannot use the
  static token until the limit clears, so `MCP_AUTH_TOKEN` cannot be guessed. Expired or foreign
  OAuth tokens never count.
- The global sign-in ceiling depends on how people sign in: with the owner's password it blocks
  everyone (as mcp-icloud did); with per-person credentials only addresses that failed themselves
  (as mcp-companies-house did). See `guards::Ceiling`.
- Successful sign-in answers `303 See Other` (RFC 9700), not `302 Found`.
- The owner's password is compared exactly as typed; credentials for upstream services are trimmed.
- Random token ids no longer need the `uuid` crate.

[0.1.0]: https://github.com/Trozz/mcp-server-core-rs/releases/tag/v0.1.0
