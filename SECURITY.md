# Security

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: on the repository's **Security** tab,
choose **Report a vulnerability**. Do not open a public issue.

You should get a reply within a week. Fixes are released as patch versions and announced in a
GitHub security advisory once a fixed version is available.

## Supported versions

Only the latest minor version receives security fixes until 1.0.

## Threat model

`mcp-server-core` is meant to be exposed to the internet, in front of tools that act on someone's
behalf. It defends against:

- **Unauthenticated access.** Every service requires an OAuth access token issued for that
  service (RFC 8707 audience binding), the static token, or a credential the verifier accepts.
- **Guessing.** Failed sign-ins, rejected bearer credentials and wrong static tokens count towards
  a per-address limit (5 a minute; IPv6 by /64); a blocked address cannot sign in, even
  correctly, until the limit clears. Failures across all addresses are capped at 30 a minute too.
  With one shared secret (the owner's password, the static token) reaching that cap blocks
  everyone, the owner included, for the rest of the minute, so a botnet gains nothing from more
  addresses (clients that already hold an OAuth access token keep working; the static token and
  the sign-in page wait). With per-person credentials it blocks only addresses that have failed themselves, so
  an attacker cannot lock other people out. Secrets are compared in constant time.
- **Abusing the upstream service through the server.** Credentials of an implausible shape are
  refused locally; upstream checks are capped, timed out and shared per credential; verdicts on
  bearer credentials are cached under the credential's SHA-256.
- **Authorization code interception and CSRF.** PKCE S256 is required; codes are one-time and
  short-lived; the sign-in form is bound to its exact request; redirect URIs must be registered
  and be `https` or loopback.
- **Clickjacking and leaks from the sign-in page.** It sends `X-Frame-Options: DENY`, a strict
  CSP, `no-store` and `no-referrer`, escapes every value, shows where the person will be sent and
  marks the client's name as unverified.
- **DNS rebinding and cross-site requests.** The MCP endpoints check `Host` and `Origin`.
- **One person reaching another's session.** MCP sessions are bound to the credential that
  opened them; a session id is useless with any other credential, and nobody can push other
  people's sessions out.
- **Credential exposure.** Upstream credentials are never stored: they are encrypted
  (ChaCha20-Poly1305) inside tokens, never written to logs, and redacted from `Debug` output.
  rmcp targets that log session ids are capped.

Out of scope, and the operator's responsibility:

- Keeping `OAUTH_SIGNING_KEY` secret. Whoever has it can mint tokens and open every sealed
  credential. Rotating it signs everyone out.
- TLS in front of the server, and setting `TRUSTED_PROXIES` only to proxies you run (otherwise
  clients can choose the address they are rate limited as).
- Choosing a strong `OAUTH_ADMIN_PASSWORD` and a long random `MCP_AUTH_TOKEN`.
- Limits shared across replicas: each replica keeps its own sign-in limits and one-time code
  memory.
- What your tools do with the access they are given. Mark tools that only read with
  `read_only_hint = true`, so read-only mode and the audit log treat the rest as writes.
