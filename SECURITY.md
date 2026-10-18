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
  a per-address limit (5 a minute; IPv6 by /64), and a blocked address cannot sign in or use the
  static token, even correctly, until the limit clears. Failures across all addresses are capped
  at 30 a minute too. With one shared secret (the owner's password, the static token) reaching
  that cap blocks everyone, the owner included, while the attack lasts, so a botnet gains nothing
  from more addresses; clients that already hold an OAuth token keep working. With per-person
  credentials the cap blocks only addresses that have failed themselves, so an attacker cannot
  lock other people out. Bearer tokens that could not be a guess at anything (junk sent to a
  server with no static token, or this server's own expired tokens) are refused without counting,
  so they cannot be used to lock anyone out. Secrets are compared in constant time.
- **Abusing the upstream service through the server.** Credentials of an implausible shape are
  refused locally; at most 60 new credential checks start a minute across every address, at most
  16 run at once, each is timed out and shared by everyone presenting the same credential;
  verdicts on bearer credentials are cached under the credential's SHA-256. A credential found
  valid in the last ten minutes is let in even from a blocked address: its holder has already
  proved possession, and blocking it would only hurt people behind a shared address.
- **Grants outliving the sign-in.** Every code, access and refresh token carries a keyed hash of
  how people sign in (`ver`) and when this person signed in (`auth_time`). Changing the owner's
  password or switching sign-in mode ends every earlier grant, and every grant ends 90 days after
  sign-in however often it is refreshed. A token minted for one sign-in mode is refused by a
  server in another, even with the same key and URL.
- **Authorization code interception and CSRF.** PKCE S256 is required; codes are one-time and
  short-lived; the sign-in form is bound to its exact request; redirect URIs must be registered,
  be `https` or loopback, and are capped in number and length; responses carry `iss` (RFC 9207).
- **Clickjacking and leaks from the sign-in page.** It sends `X-Frame-Options: DENY`, a strict
  CSP, `no-store` and `no-referrer`, escapes every value, shows where the person will be sent and
  marks the client's name (capped at 200 characters) as unverified. Every response sends
  `X-Content-Type-Options: nosniff`, and HSTS when the server terminates TLS itself.
- **DNS rebinding and cross-site requests.** The MCP endpoints check `Host` and `Origin`.
- **One person reaching another's session.** MCP sessions are bound to the credential that
  opened them; a session id is useless with any other credential, and nobody can push other
  people's sessions out.
- **Credential exposure.** Upstream credentials are never stored: they are encrypted
  (ChaCha20-Poly1305) inside tokens, never written to logs, and redacted from `Debug` output.
  Logs and the audit log name people by a subject such as `key:` and a short hash, never the
  credential. rmcp targets that log session ids are capped.

## What a stateless server cannot do

Nothing is stored, so restarts and replicas need only the configuration. The price:

- **No refresh-token reuse detection.** OAuth 2.1 asks an authorization server to notice when an
  old refresh token is used again and revoke the grant; that needs a record of every grant. A
  stolen refresh token works until it expires, the grant reaches its 90 days, the owner's
  password changes or `OAUTH_SIGNING_KEY` is rotated.
- **No revoking one person or one client.** Revocation is all or nothing: rotate
  `OAUTH_SIGNING_KEY` (everyone signs in again, and clients register again) or, with the owner's
  password, change the password (everyone signs in again).
- **Limits are per replica.** Each replica keeps its own sign-in limits and one-time-code memory.
- **No request rate limiting.** Limit request rates at your reverse proxy or with a tower layer
  around `Server::router`. Do not limit `/mcp`, `/<service>`, `/token` or `/register` per client
  address if hosted clients such as claude.ai use the server: they reach it from a few shared
  addresses, so one busy person would block everyone.

For single sign-on, MFA or many named users, put an identity-aware gateway (Cloudflare Access,
oauth2-proxy and the like) in front of `/authorize`; that is the only page a person's browser
opens.

## Out of scope, and the operator's responsibility

- Keeping `OAUTH_SIGNING_KEY` secret. Whoever has it can mint tokens and open every sealed
  credential.
- TLS in front of the server, and setting `TRUSTED_PROXIES` only to proxies you run (otherwise
  clients can choose the address they are rate limited as).
- Choosing a strong `OAUTH_ADMIN_PASSWORD` (the server warns below 15 characters) and a long
  random `MCP_AUTH_TOKEN` (it warns below 32).
- What your tools do with the access they are given. Mark tools that only read with
  `read_only_hint = true`, so read-only mode and the audit log treat the rest as writes.
