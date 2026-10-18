# Limits and abuse protection

The server limits what one address, one network and everyone together can cost it: failed sign-ins, upstream credential checks, MCP sessions, request bodies and client registrations. This page gives every limit with its exact number and window, what counts towards it, and what a client sees when it is refused.

## Every limit at a glance

| Limit | Value | Constant |
|---|---|---|
| Attempts per address (IPv4 address, IPv6 /64) | 5 in any 60 seconds | [`oauth::LOGIN_ATTEMPTS`](https://docs.rs/mcp-server-core/latest/mcp_server_core/oauth/constant.LOGIN_ATTEMPTS.html), [`oauth::LOGIN_WINDOW`](https://docs.rs/mcp-server-core/latest/mcp_server_core/oauth/constant.LOGIN_WINDOW.html) |
| Attempts per block (IPv4 /24, IPv6 /48) | 25 in any 60 seconds | [`guards::BLOCK_MAX_ATTEMPTS`](https://docs.rs/mcp-server-core/latest/mcp_server_core/guards/constant.BLOCK_MAX_ATTEMPTS.html) |
| Global ceiling: rejections across all addresses | 30 in any 60 seconds | [`guards::GLOBAL_MAX_FAILURES`](https://docs.rs/mcp-server-core/latest/mcp_server_core/guards/constant.GLOBAL_MAX_FAILURES.html) |
| Addresses, and separately blocks, tracked at once | 10,000 each | not public |
| Credential checks running at once | 16 | [`oauth::MAX_RUNNING_CHECKS`](https://docs.rs/mcp-server-core/latest/mcp_server_core/oauth/constant.MAX_RUNNING_CHECKS.html) |
| Longest a check may run | 15 seconds | [`oauth::CHECK_TIMEOUT`](https://docs.rs/mcp-server-core/latest/mcp_server_core/oauth/constant.CHECK_TIMEOUT.html) |
| Longest a check waits for a free slot | 5 seconds | [`oauth::CHECK_SLOT_WAIT`](https://docs.rs/mcp-server-core/latest/mcp_server_core/oauth/constant.CHECK_SLOT_WAIT.html) |
| A bearer credential found valid is trusted for | 10 minutes | [`oauth::BEARER_VALID_FOR`](https://docs.rs/mcp-server-core/latest/mcp_server_core/oauth/constant.BEARER_VALID_FOR.html) |
| A rejected bearer credential is remembered for | 60 seconds | [`oauth::BEARER_INVALID_FOR`](https://docs.rs/mcp-server-core/latest/mcp_server_core/oauth/constant.BEARER_INVALID_FOR.html) |
| Verdicts cached at once | 10,000 | not public |
| Longest credential (default shape check) | 256 bytes of visible ASCII | [`credential::MAX_CREDENTIAL_LEN`](https://docs.rs/mcp-server-core/latest/mcp_server_core/credential/constant.MAX_CREDENTIAL_LEN.html) |
| Longest owner's password considered | 1,024 bytes | [`credential::MAX_PASSWORD_LEN`](https://docs.rs/mcp-server-core/latest/mcp_server_core/credential/constant.MAX_PASSWORD_LEN.html) |
| MCP sessions per credential, on each path | 50 | not public |
| MCP sessions on each path | 10,000 | not public |
| A session's entry is treated as idle after | 360 seconds | not public |
| Request body, on `/healthz`, the OAuth routes and the MCP endpoints | 1 MiB (1,048,576 bytes) | [`server::BODY_LIMIT`](https://docs.rs/mcp-server-core/latest/mcp_server_core/server/constant.BODY_LIMIT.html) |
| Redirect URIs per registered client | 1 to 10 | [`oauth::MAX_REDIRECT_URIS`](https://docs.rs/mcp-server-core/latest/mcp_server_core/oauth/constant.MAX_REDIRECT_URIS.html) |
| Length of one redirect URI | 2,048 bytes | [`oauth::MAX_REDIRECT_URI_LEN`](https://docs.rs/mcp-server-core/latest/mcp_server_core/oauth/constant.MAX_REDIRECT_URI_LEN.html) |
| Length of a client name | 200 characters | [`oauth::MAX_CLIENT_NAME_CHARS`](https://docs.rs/mcp-server-core/latest/mcp_server_core/oauth/constant.MAX_CLIENT_NAME_CHARS.html) |
| `Retry-After` on every 429 and 503 | 30 seconds | not public |

Token lifetimes and the 90-day grant limit are on [OAuth and tokens](oauth.md#tokens). Counts, caches and session tables live in memory, and each replica keeps its own.

Your code can read the public numbers from the constants:

```rust
use mcp_server_core::credential::{MAX_CREDENTIAL_LEN, MAX_PASSWORD_LEN};
use mcp_server_core::guards::{BLOCK_MAX_ATTEMPTS, GLOBAL_MAX_FAILURES};
use mcp_server_core::oauth::{
    BEARER_INVALID_FOR, BEARER_VALID_FOR, CHECK_SLOT_WAIT, CHECK_TIMEOUT, LOGIN_ATTEMPTS,
    LOGIN_WINDOW, MAX_CLIENT_NAME_CHARS, MAX_REDIRECT_URI_LEN, MAX_REDIRECT_URIS,
    MAX_RUNNING_CHECKS,
};
use mcp_server_core::server::BODY_LIMIT;
use std::time::Duration;

assert_eq!(LOGIN_ATTEMPTS, 5);
assert_eq!(LOGIN_WINDOW, Duration::from_secs(60));
assert_eq!(BLOCK_MAX_ATTEMPTS, 25);
assert_eq!(GLOBAL_MAX_FAILURES, 30);
assert_eq!(MAX_RUNNING_CHECKS, 16);
assert_eq!(CHECK_TIMEOUT, Duration::from_secs(15));
assert_eq!(CHECK_SLOT_WAIT, Duration::from_secs(5));
assert_eq!(BEARER_VALID_FOR, Duration::from_secs(600));
assert_eq!(BEARER_INVALID_FOR, Duration::from_secs(60));
assert_eq!(MAX_CREDENTIAL_LEN, 256);
assert_eq!(MAX_PASSWORD_LEN, 1024);
assert_eq!(BODY_LIMIT, 1024 * 1024);
assert_eq!(MAX_REDIRECT_URIS, 10);
assert_eq!(MAX_REDIRECT_URI_LEN, 2048);
assert_eq!(MAX_CLIENT_NAME_CHARS, 200);
```

## Sign-in attempts

One limiter guards everything a person can guess at: the sign-in page, credentials sent as bearer tokens and the static token. It counts attempts per address, per block of addresses and across all of them.

### What counts as an attempt

An attempt is counted when its check starts, so concurrent attempts share the limits too. When the check ends, a rejection keeps counting and anything else is given back.

| Request | Counts? |
|---|---|
| A credential submitted on the sign-in page (`POST /authorize`) | Yes, from when its check starts. Kept if rejected; given back if accepted or if it could not be checked. |
| A credential sent as the bearer token, with no cached verdict | Yes, in the same way. |
| A bearer token on a server with `MCP_AUTH_TOKEN` set, when the token is not shaped like a JWT | Yes, before it is compared. Kept if it is wrong; given back if it is the static token. |
| This server's own tokens, including expired ones, ones for another path and ones from a grant that has ended | Never. They get 401 and are never sent upstream. |
| A token shaped like a JWT, when the verifier does not accept bearer credentials | Never. It gets 401. |
| Any bearer token on a server that accepts neither bearer credentials nor a static token, such as an owner's-password server without `MCP_AUTH_TOKEN` | Never. It could not be a guess at anything, so it gets 401 without counting and cannot lock anyone out. |
| Input that cannot be a credential: empty, too long or, for the default shape check, not visible ASCII | Never. It is refused locally; the sign-in page says `That is not a <label>.` |
| A request with the same credential as a check already running | Never. It waits for that check and shares its verdict. |
| A bearer credential with a cached verdict | Never. A valid one passes; a rejected one gets 401 without counting again. |
| A request with an OAuth access token | Never, and the limits never refuse it. |
| `GET /authorize`, `/token`, `/register`, the metadata documents, `/healthz` | Never. |

The verifier decides the shape check through `plausible`, and the owner's password accepts anything from 1 to 1,024 bytes. [The CredentialVerifier trait](sign-in.md#the-credentialverifier-trait) describes `plausible`, and [Credentials sent as bearer tokens](sign-in.md#credentials-sent-as-bearer-tokens) the order in which the bearer check tries a token.

A check runs in a task of its own, so a client that disconnects in the middle does not stop it: the attempt is still kept or given back, and a bearer credential's verdict is still cached.

### Per address

An address is an IPv4 address or an IPv6 /64, since one IPv6 host usually holds a whole /64. An IPv4-mapped IPv6 address, such as `::ffff:203.0.113.7` from a dual-stack listener, counts as its IPv4 address.

Each address may have at most 5 attempts in any 60 seconds, counting rejected ones and those still being checked. Each attempt stops counting 60 seconds after its check started. The sixth is refused with 429, and so is every further attempt from that address until one ages out:

- the sign-in page refuses it before looking at the request, even with the right password or credential;
- the static token is refused, even the right one;
- a credential sent as the bearer token is refused, unless it was found valid in the last 10 minutes: its holder has already proved possession, and refusing it would only hurt people behind a shared address.

OAuth access tokens already issued keep working throughout. A person who has connected a client is never locked out by the limits; only signing in again, or using the static token, waits.

Five checks in flight from one address also use up its allowance, so a sixth concurrent check is refused rather than queued.

### Per block

A block is an IPv4 /24 or an IPv6 /48: the allocation one network usually controls. Each block may have at most 25 attempts in any 60 seconds, rejected or in flight, whatever addresses within it they come from. The 26th is refused with 429 for every address in the block.

Without it, a network holding a /48 could try 5 guesses from each of its 65,536 /64s. With it, one network can make at most 25 rejected checks a minute. People who share a block with an attacker can be held up by the block limit while the attack lasts.

### The global ceiling

Across all addresses, the server counts rejections (not attempts in flight, so a busy server never trips it by itself). When 30 rejections have been recorded in the last 60 seconds, the ceiling is reached, and what happens next depends on how people sign in. The mode is [`guards::Ceiling`](https://docs.rs/mcp-server-core/latest/mcp_server_core/guards/enum.Ceiling.html), chosen by the verifier's `carried()`:

| Mode | Chosen when | Once the ceiling is reached |
|---|---|---|
| `Ceiling::BlockEveryone` | Credentials are not carried: the owner's password, or any verifier whose `carried()` is `false` | Every attempt from every address is refused with 429, the owner's included, until fewer than 30 rejections remain in the last 60 seconds. |
| `Ceiling::BlockFailing` | Credentials are carried: the verifier's `carried()` is `true`, its default, as for a typical `SignIn::ServiceCredential` or custom verifier | Only addresses with a rejection of their own in the last 60 seconds are refused, even after a single one. Everyone else signs in as usual, apart from the case below. |

The difference follows from what a guess is worth:

- **One shared secret.** With the owner's password, or the static token beside it, one right guess gives everything away. Blocking everyone keeps the total guessing rate at 30 a minute however many addresses an attacker controls, so a botnet gains nothing from more addresses. The price: someone who keeps failing can keep the owner out of the sign-in page and the static token for as long as they keep it up. Clients that already hold OAuth tokens keep working.
- **Per-person credentials.** Each guess is against one key among many, checked upstream. Blocking everyone would let an attacker lock out every other person, so only addresses that failed themselves wait.

### When very many addresses are failing

The limiter tracks at most 10,000 addresses and 10,000 blocks that have attempts in the last 60 seconds, and forgets each one once its attempts age out (it sweeps at most once a second). When the address table is full, an address it is not already tracking is not counted on its own: it is limited by its block's 25 alone, when the block can be tracked. Once the global ceiling is also reached:

- it is refused with 429 if its block has a rejection in the last 60 seconds;
- if the block table is full too and its block is not tracked, it is refused with 503: the server is under attack from so many networks that it cannot tell a new address apart, and refuses new ones until the attack calms down.

Below the ceiling, a full table refuses nothing extra. In practice this matters only in `Ceiling::BlockFailing` mode: in `Ceiling::BlockEveryone` mode the ceiling has already refused everyone.

### Which address

The address is the TCP peer, unless the peer is listed in `TRUSTED_PROXIES`. Then it is the client address the proxy reports in `X-Forwarded-For`, read from the right; [How X-Forwarded-For is read](deployment.md#how-x-forwarded-for-is-read) gives the exact rules, with examples. IPv4-mapped IPv6 addresses count as their IPv4 address.

Behind a reverse proxy, set `TRUSTED_PROXIES` to the proxy's address. Otherwise every request arrives from the proxy, every client shares one address's allowance, and five failures anywhere lock out everyone. Never list an address you do not run: a client that can set `X-Forwarded-For` through a trusted address chooses the address it is limited as. [TLS and deployment](deployment.md) covers proxies.

## Credential checks

Every credential the verifier checks, on the sign-in page or as a bearer token, goes through one runner. For a verifier that asks an upstream service, this bounds how much work the server can be made to send there.

| Rule | Effect |
|---|---|
| At most 16 checks run at once | Across the sign-in page and bearer credentials together. |
| A check waits up to 5 seconds for a free slot | Then it gives up as unavailable: `the server is checking too many credentials at once`. |
| A running check may take up to 15 seconds | Then it is unavailable: `the check timed out`. |
| One check at a time per credential | Requests with a credential that is already being checked wait for that check and share its verdict. Only the first counts towards the limits, and only it calls the verifier. |

Checks in progress are keyed by the credential's SHA-256, never the credential itself. An unavailable verdict is never held against the person: the attempt is given back, nothing is cached, and the client is told to try again. If the first request for a credential is refused by the limits, the requests waiting on it are told `too many attempts from this address; try again shortly`, as an unavailable verdict. A waiting request whose leading check went away without a verdict is told `the check was abandoned`, and a check whose task failed gives `the check stopped unexpectedly`.

There is deliberately no global cap on new checks. Anyone with enough networks could use such a cap up to keep everyone else from signing in. An attacker with many networks can therefore still make the server send many junk credentials upstream, 25 a minute from each block; if that matters, limit it at the network. Narrowing `plausible` to the upstream service's real credential format means junk of another shape is refused locally without a check.

## Verdict cache

Verdicts on credentials sent as bearer tokens are cached under the credential's SHA-256, so a client that sends its key on every request is not checked upstream every time. The sign-in page always checks.

| Verdict | Cached for | While cached |
|---|---|---|
| Valid | 10 minutes | The credential passes without a check, even from an address the limits are refusing. |
| Rejected | 60 seconds | The credential gets 401 without a check and without counting again. |
| Unavailable | not cached | The next request checks again. |

The cache holds at most 10,000 verdicts. When it is full, expired entries go first, then rejected ones; if every entry is a current valid one, a new rejection is not cached and a new valid verdict replaces the one closest to expiry. A burst of junk keys can never push out keys that work.

One consequence: a key revoked upstream keeps passing the bearer check for up to 10 minutes. It gains nothing by it, since the upstream service refuses the key when a tool uses it.

## MCP sessions

An MCP session starts with `initialize` and is named by the `Mcp-Session-Id` header after that. Each path, every `/<service>` and `/mcp`, keeps its own table of sessions and its own limits, so a person using `/notes` and `/mcp` has an allowance on each.

When credentials are carried, as when people sign in with their own credentials, each session belongs to the credential that opened it (the `Credential` the bearer guard added), by its SHA-256:

- A request that names a session opened with another credential gets `404 Session not found`, exactly as for a session that does not exist, so the client starts a new one. Nobody can use or end someone else's session, even knowing its id.
- One credential may hold 50 sessions on a path. Opening a 51st closes that credential's least recently used session.
- A path holds 10,000 sessions. When the table is full, the server first clears entries unused for 360 seconds and sessions rmcp has already ended (at most once a second). If it is still full, the credential holding the most sessions gives up its least recently used one, provided it holds at least two more than the newcomer. Otherwise a newcomer that already holds sessions replaces its own oldest. A newcomer with no sessions is refused only when nobody else holds more than one, with 503 and `This server has too many open sessions. Try again shortly.`

Fair shares mean nobody is pushed out by someone holding fewer sessions, and a few hundred credentials opening sessions cannot lock everyone else out. When the table is full and was swept less than a second ago, a refusal is decided before rmcp builds the session, so refused requests cost little.

An entry unused for 360 seconds, a little longer than rmcp's own five-minute idle timeout, is checked against rmcp when it is next used: if rmcp still holds the session, as during a long tool call, it carries on; otherwise the request gets 404. A successful `DELETE` removes the session from the table.

Without carried credentials, as with the owner's password or the static token, every session on a path has the same owner: there is no per-credential cap, and only the 10,000 sessions per path and the sweep apply. When all 10,000 are in use after the sweep, new sessions are refused with 503 until some go idle or end. With the owner's password there is one person, so this costs nothing; a custom verifier whose `carried()` is `false` but which lets several people sign in gets neither the separation nor the fair shares.

## Request bodies

Every route `server::build_app` mounts, `/healthz`, `/register`, `/token`, `/authorize` and the MCP endpoints, refuses a request body larger than 1 MiB (1,048,576 bytes). A request whose `Content-Length` declares more gets `413 Payload Too Large` with the body `length limit exceeded`, before the body is read. A longer body sent without a declared length is cut off at the limit: the OAuth routes answer 413, and the MCP endpoints answer 500. rmcp's transport is configured with the same limit for the JSON it reads. Routes you add with `Server::wrap_router`, and `/favicon.ico`, are outside this layer, so give them a limit of their own. [Body limits](deployment.md#body-limits) quotes every answer and shows how to match the limit at your proxy.

## Client registration

`POST /register` is open to anyone, as dynamic client registration requires. It stores nothing: a registration is a token signed by the server, so it costs one signature, and the server caps what one may contain. A refusal is `400 Bad Request` with a JSON `error` and `error_description`, checked in this order:

| Field | Limit | Refused with |
|---|---|---|
| the body | a JSON client registration | `invalid_client_metadata`: `send a JSON client registration with redirect_uris` |
| `client_name` | optional; at most 200 characters, no control characters | `invalid_client_metadata`: `client_name must be at most 200 characters, without control characters` |
| `redirect_uris` | 1 to 10 URIs, each at most 2,048 bytes, `https` with a host or `http` on `localhost`, `127.0.0.1` or `[::1]`, without a fragment or user information | `invalid_redirect_uri`: `redirect_uris must be 1 to 10 https URIs (http only on a loopback host), at most 2048 bytes each, without fragments or userinfo` |

A body over 1 MiB gets 413 instead.

The sign-in page shows the client name marked as self-reported and unverified. [Dynamic client registration](oauth.md#dynamic-client-registration) describes the endpoint.

## Refusals: 429 and 503

Every 429 and 503 carries `Retry-After: 30`. It is a hint, not the exact time: an address's attempts age out one by one, up to 60 seconds after each started.

| Status | Body | Cause | What to do |
|---|---|---|---|
| 429 | `Too many attempts from this address: credentials or tokens were rejected, or several are being checked at once. Try again shortly.` | A bearer token or credential from an address or block over its limit, or any attempt once the ceiling blocks everyone. | Wait. Find out who is failing from the warnings in the log. |
| 429 | Sign-in page: `Too many attempts from this address: credentials were rejected, or several are being checked at once. Wait a little and try again.` | The same, on the sign-in page. | Wait, then sign in again. |
| 503 | `Your <label> could not be checked right now: <why>` (the sign-in page shows the same sentence above the form) | The credential could not be checked: the verifier said so, the check timed out, every slot stayed busy for 5 seconds, or the check this request was waiting on was refused. | Try again. If it persists, check the upstream service. |
| 503 | `Your <label> could not be checked right now: the server is refusing new addresses while it is under heavy load; try again shortly` (sign-in page: `This server is refusing new addresses while it is under heavy load. Try again shortly.`) | The server is under attack from too many networks to track. | Wait for the attack to pass, or filter it at the network. |
| 503 | `This server has too many open sessions. Try again shortly.` | The path's session table is full, and no session can fairly make room; see [MCP sessions](#mcp-sessions). | Try again; idle sessions are cleared after 360 seconds. |
| 413 | `length limit exceeded` when `Content-Length` is over the limit | A request body over 1 MiB; see [Request bodies](#request-bodies) for a body without a declared length. No `Retry-After`. | Send less. |

In short, 429 is about attempts: too many from this address or its block were rejected or are still being checked, or, in `Ceiling::BlockEveryone` mode (the owner's password), too many from everyone were rejected. Waiting is the answer. 503 means the server or the upstream service cannot take the request now, through no fault of the caller. `<label>` is the verifier's name for the credential, such as `password` or `Example API key`, and `<why>` is the verifier's reason or one of the reasons in [Credential checks](#credential-checks).

To see the limits at work:

| Metric | Counts |
|---|---|
| `bearer_credential_checks_total{outcome="rate_limited"}` | Bearer tokens and static tokens refused by the limits. `outcome` is also `valid`, `invalid` or `unavailable` for checked credentials. |
| `oauth_requests_total{endpoint="authorize",outcome="rate_limited"}` | Sign-in attempts refused by the limits. `outcome` is also `unavailable` or `ok`. |
| `oauth_login_failures_total` | Rejected sign-ins on the sign-in page. |
| `http_requests_total{route,status}` | Responses of `server::build_app`'s routes by matched route and status code, so 429 and 503 responses show here too. A 413 refused on its `Content-Length` is answered before this counter. |

The log records each rejection as a warning with the client's address: `wrong static token rejected`, `bearer credential rejected` and `oauth login failed: credential rejected`. A credential that could not be checked is logged as `bearer credential could not be checked`, with its reason, or on the sign-in page as `oauth login: credential could not be checked`, with the address and the reason. Refusals by the limits themselves are not logged; watch the `rate_limited` metrics. [Observability](observability.md) has every metric and log line, and [Troubleshooting](troubleshooting.md) how to work from them.

## What the server does not limit

- **Request rates.** The server limits guesses and credential checks, not how often a signed-in client calls tools. Limit request rates at your reverse proxy, or with a tower layer added through `Server::wrap_router`. Do not limit `/mcp`, `/<service>`, `/token` or `/register` per client address if hosted clients such as claude.ai use the server: they reach it from a few shared addresses, so one busy person would block everyone. Limit per bearer token instead, and per address only on `/authorize`, the page a person's browser opens. [nginx](deployment.md#nginx) has a configuration that does this.
- **Across replicas.** Each replica keeps its own counts, caches and session tables. Behind a load balancer with three replicas, an address can make 5 attempts a minute on each.
- **What tools do upstream.** A signed-in person can call tools as often as the request rate allows; your service and the upstream service's own limits decide what that costs.

## Using the limiter yourself

The server's limiter is internal, but the type is public, in [`guards`](https://docs.rs/mcp-server-core/latest/mcp_server_core/guards/index.html), for a route of your own that checks something guessable, such as one added with `Server::wrap_router`. Reserve an attempt before checking, then settle it:

```rust
use mcp_server_core::guards::{Ceiling, LoginLimiter, Refusal};
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

/// Counts the attempt before checking, then keeps it only if it was wrong.
fn try_code(limiter: &LoginLimiter, client: IpAddr, right: bool) -> Result<bool, Refusal> {
    let attempt = limiter.try_reserve(client)?;
    if right {
        limiter.refund(attempt);
    } else {
        limiter.fail(attempt);
    }
    Ok(right)
}

let limiter = LoginLimiter::new(5, Duration::from_secs(60), Ceiling::BlockEveryone);

// Five wrong codes from five addresses in one IPv6 /64: one client, so its allowance is spent.
for host in 1..=5 {
    let client = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 0, 0, 0, host));
    assert_eq!(try_code(&limiter, client, false), Ok(false));
}
let same_client: IpAddr = "2001:db8:1:2::99".parse().unwrap();
assert_eq!(try_code(&limiter, same_client, true), Err(Refusal::TooMany));

// Another /64 is another client.
let neighbour: IpAddr = "2001:db8:1:3::1".parse().unwrap();
assert_eq!(try_code(&limiter, neighbour, true), Ok(true));
```

`LoginLimiter::new` takes the per-address allowance, the window and the ceiling mode; the block limit of 25, the ceiling of 30 rejections and the 10,000 tracked addresses and blocks are fixed. `refusal(ip)` and `is_blocked(ip)` ask without counting, and `record_failure(ip)` records a rejection that was not reserved first. Settle every reservation with `fail` or `refund`: one that is dropped keeps counting until its window passes.
