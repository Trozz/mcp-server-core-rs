# Sign-in modes

This page covers who may use a server and what your tools receive about them: the three sign-in modes, the `CredentialVerifier` trait behind them, sealed credentials, credentials sent directly as bearer tokens, the static token and the `Caller` every request carries. The OAuth flow itself is on [OAuth and tokens](oauth.md).

## Choosing a mode

You choose how people sign in with [`Server::sign_in`](https://docs.rs/mcp-server-core/latest/mcp_server_core/app/struct.Server.html#method.sign_in) and an [`app::SignIn`](https://docs.rs/mcp-server-core/latest/mcp_server_core/app/enum.SignIn.html):

| Mode | Who signs in | What tools get | Use it for |
|---|---|---|---|
| `SignIn::OwnerPassword` (the default) | One person, with `OAUTH_ADMIN_PASSWORD`. `MCP_AUTH_TOKEN` can also be set for clients that cannot do OAuth. | Nothing about the person: tools act with the server's own upstream configuration, such as an app password in the environment. | A personal server, such as [mcp-icloud](https://github.com/Trozz/mcp-icloud). |
| `SignIn::ServiceCredential` | Anyone with a credential the upstream service accepts, checked by the verifier one of your services returns from `Service::credential_verifier`. | The person's own credential, as a [`Credential`](https://docs.rs/mcp-server-core/latest/mcp_server_core/credential/struct.Credential.html) in the request extensions. | One deployment shared by many people, each with their own API key, such as [mcp-companies-house](https://github.com/Trozz/mcp-companies-house). |
| `SignIn::Custom(fn)` | Whoever the `CredentialVerifier` your function builds accepts. | Either of the above, depending on the verifier's `carried()`. | Sign-in that needs its own configuration or does not belong to one service. |

Every mode uses the same sign-in page and the same OAuth flow. Only the field on the page, the check behind it and what the tokens carry differ.

```rust
# use mcp_server_core::service::{Service, ServiceEnv};
# use std::sync::Arc;
# fn notes(_: &mut ServiceEnv) -> Option<Arc<dyn Service>> { None }
use mcp_server_core::app::{Server, SignIn};

let server = Server::new("mcp-notes", "1.0.0")
    .env_prefix("NOTES")
    .service("notes", notes)
    .sign_in(SignIn::OwnerPassword);
# let _ = server;
```

`SignIn` is `#[non_exhaustive]`, so a later version can add modes without a breaking change.

### The owner's password

With `SignIn::OwnerPassword` the server reads `OAUTH_ADMIN_PASSWORD` and builds a [`PasswordVerifier`](https://docs.rs/mcp-server-core/latest/mcp_server_core/credential/struct.PasswordVerifier.html) from it.

- The password must be at least 12 characters ([`app::MIN_ADMIN_PASSWORD_CHARS`](https://docs.rs/mcp-server-core/latest/mcp_server_core/app/constant.MIN_ADMIN_PASSWORD_CHARS.html)) and not only white space. Otherwise the server stops with `OAUTH_ADMIN_PASSWORD must be at least 12 characters, not only spaces`, or `OAUTH_ADMIN_PASSWORD is required` when it is unset.
- A password of 12 to 14 characters starts the server with a warning ([`app::RECOMMENDED_ADMIN_PASSWORD_CHARS`](https://docs.rs/mcp-server-core/latest/mcp_server_core/app/constant.RECOMMENDED_ADMIN_PASSWORD_CHARS.html) is 15): `OAUTH_ADMIN_PASSWORD is shorter than 15 characters: a longer passphrase is much harder to guess`.
- It can be given as a file with `OAUTH_ADMIN_PASSWORD_FILE`, like every other variable; see [Configuration reference](configuration.md).
- It is compared exactly as typed, spaces included, in constant time. Empty input, or input longer than 1,024 bytes ([`credential::MAX_PASSWORD_LEN`](https://docs.rs/mcp-server-core/latest/mcp_server_core/credential/constant.MAX_PASSWORD_LEN.html)), is refused without a comparison.
- It only proves who is signing in. It never enters a token and is never accepted as a bearer token.
- Changing it ends every earlier sign-in: each connector asks the person to sign in again, without being added again (see [What ends a grant](oauth.md#what-ends-a-grant)).

Generate a passphrase rather than a word, for example with a password manager. One shared secret guards everything, so the server treats a burst of failures differently from per-person sign-in; see [Limits and abuse protection](limits.md).

### Each person's own credential

With `SignIn::ServiceCredential` each person signs in with their own credential for the upstream API your tools call. The server:

1. asks the person for it on the sign-in page, named by the verifier's label ("Sign in with your own Example API key");
2. checks it once upstream with the verifier;
3. seals it into the person's OAuth tokens (see [Sealed credentials](#sealed-credentials));
4. opens it again on every request and hands it to your tools as a `Credential`.

`OAUTH_ADMIN_PASSWORD` is not read in this mode. Clients that can set a header may skip OAuth and send the credential itself as their bearer token (see [Credentials sent as bearer tokens](#credentials-sent-as-bearer-tokens)).

The verifier comes from the service that defines how people sign in:

```rust,no_run
use mcp_server_core::app::{Server, SignIn};
use mcp_server_core::combined::DynHandler;
use mcp_server_core::credential::CredentialVerifier;
use mcp_server_core::service::{Service, ServiceEnv};
use std::sync::Arc;
# use mcp_server_core::credential::{CheckFuture, CredentialCheck};
# #[derive(Clone)]
# struct ExampleTools;
# impl mcp_server_core::rmcp::ServerHandler for ExampleTools {}
# struct ExampleKeys;
# impl CredentialVerifier for ExampleKeys {
#     fn label(&self) -> &str { "Example API key" }
#     fn check<'a>(&'a self, _: &'a str) -> CheckFuture<'a> { Box::pin(async { CredentialCheck::Valid }) }
# }

struct ExampleService;

impl Service for ExampleService {
    fn name(&self) -> &'static str {
        "example"
    }
    fn handler(&self) -> DynHandler {
        DynHandler::new(ExampleTools)
    }
    fn credential_verifier(&self) -> Option<Arc<dyn CredentialVerifier>> {
        Some(Arc::new(ExampleKeys))
    }
}

fn example(_env: &mut ServiceEnv) -> Option<Arc<dyn Service>> {
    Some(Arc::new(ExampleService))
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    Server::new("mcp-example", env!("CARGO_PKG_VERSION"))
        .env_prefix("EXAMPLE")
        .service("example", example)
        .sign_in(SignIn::ServiceCredential)
        .main()
        .await
}
```

Every service on the server receives the credential, including services that do not define a verifier, and so does the combined `/mcp` endpoint.

### Only one service may define sign-in

With `SignIn::ServiceCredential`, exactly one enabled service must return a verifier from `Service::credential_verifier`:

| Enabled services with a verifier | Result |
|---|---|
| None | The server stops with `no enabled service defines how people sign in`. |
| One | Its verifier decides who signs in on every path. |
| More than one | The server stops with `more than one enabled service defines how people sign in (a, b): enable one of them`. |

The rule exists because there is one sign-in page and one credential per person. With two verifiers, each service's tools would receive a credential meant for another upstream. The check counts only enabled services, so you can register several services that each define a verifier and run one at a time with `<PREFIX>_SERVICES`.

### A verifier of your own

`SignIn::Custom` takes a function that builds the verifier from the environment, the same way a [service factory](writing-a-service.md) does. Record every problem in `env.errors` and return `None` only after recording why, so the server reports it with every other configuration error.

```rust
use mcp_server_core::app::{Server, SignIn};
use mcp_server_core::credential::{CheckFuture, CredentialCheck, CredentialVerifier};
use mcp_server_core::service::ServiceEnv;
use std::sync::Arc;
# async fn check_upstream(_api_url: &str, _key: &str) -> CredentialCheck { CredentialCheck::Valid }

/// Keys for an API whose address is configured, say a sandbox while testing.
struct ExampleKeys {
    api_url: String,
}

impl CredentialVerifier for ExampleKeys {
    fn label(&self) -> &str {
        "Example API key"
    }
    fn check<'a>(&'a self, key: &'a str) -> CheckFuture<'a> {
        // One cheap authenticated request to the configured API decides.
        Box::pin(check_upstream(&self.api_url, key))
    }
    /// A sandbox key is no key for production: pointing elsewhere signs everyone out.
    fn generation(&self) -> &[u8] {
        self.api_url.as_bytes()
    }
}

fn sign_in(env: &mut ServiceEnv) -> Option<Arc<dyn CredentialVerifier>> {
    let api_url = env.required("EXAMPLE_API_URL")?;
    if !api_url.starts_with("https://") {
        env.errors.push("EXAMPLE_API_URL must be an https URL".into());
        return None;
    }
    Some(Arc::new(ExampleKeys { api_url }))
}

let server = Server::new("mcp-example", "1.0.0").sign_in(SignIn::Custom(sign_in));
# let _ = server;
```

Use `Custom` when sign-in needs configuration that is not any one service's, or when you want a password with a different label or variable than the owner's password. A custom verifier whose `carried()` is `false` behaves like the owner's password: nothing about it enters tokens and tools get no `Credential`.

### Signing in through an upstream provider

When the upstream service has OAuth of its own, such as FreeAgent, GitHub or Google, people can sign in there instead of pasting a key. The server acts as the provider's OAuth client: a verifier whose [`upstream`](https://docs.rs/mcp-server-core/latest/mcp_server_core/credential/trait.CredentialVerifier.html#method.upstream) method returns an [`UpstreamSignIn`](https://docs.rs/mcp-server-core/latest/mcp_server_core/upstream/trait.UpstreamSignIn.html) turns the sign-in page into a consent page with a **Continue to** button, and the credential the provider grants, usually its refresh token, is sealed into the person's tokens like any carried credential. [`UpstreamVerifier`](https://docs.rs/mcp-server-core/latest/mcp_server_core/upstream/struct.UpstreamVerifier.html) builds such a verifier around your provider; return it from `Service::credential_verifier` with `SignIn::ServiceCredential`, or from a `SignIn::Custom` function.

```rust
use mcp_server_core::credential::CredentialVerifier;
use mcp_server_core::upstream::{Exchange, ExchangeFuture, UpstreamGrant, UpstreamSignIn, UpstreamVerifier};
use std::sync::Arc;

struct Ledger;

impl UpstreamSignIn for Ledger {
    fn provider(&self) -> &str {
        "Ledger"
    }
    fn authorize_url(&self, redirect_uri: &str, state: &str) -> String {
        let mut url = url::Url::parse("https://ledger.example.com/oauth/authorize").unwrap();
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", "this-server")
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("state", state);
        url.into()
    }
    fn exchange<'a>(&'a self, code: &'a str, redirect_uri: &'a str) -> ExchangeFuture<'a> {
        Box::pin(async move {
            // POST code and redirect_uri to the token endpoint; on success:
            let _ = (code, redirect_uri);
            Exchange::Granted(UpstreamGrant::new("the refresh token").with_subject("ledger:user:42"))
        })
    }
}

fn verifier() -> Arc<dyn CredentialVerifier> {
    Arc::new(UpstreamVerifier::new("Ledger account", Ledger).with_generation(b"live".to_vec()))
}
# let _ = verifier();
```

The flow, with nothing stored on the server:

1. `GET /authorize` shows which client is asking and where it will be sent, as the ordinary sign-in page does. Consent is asked here for every client: all of them reach the provider under this server's one OAuth client id, so the provider's own consent screen cannot tell them apart.
2. The button posts the form, which sets a cookie holding the pending request, encrypted under a key derived from `OAUTH_SIGNING_KEY` and bound to a random `state`, and sends the browser to `authorize_url`. The cookie is `HttpOnly`, `SameSite=Lax`, limited to `/callback`, `Secure` over https, and lasts 10 minutes.
3. The provider sends the browser back to `PUBLIC_URL/callback`. The server checks `state` against the cookie, calls `exchange` (timed out, at most 16 at once) and sends the browser on to the client with an authorization code carrying the sealed credential. A declined approval reaches the client as `access_denied`.

Register `PUBLIC_URL/callback` with the provider as a redirect URI; for local use, `http://localhost:<port>/callback`. No service may be named `callback` on such a server. An exchange the provider refuses counts as a failed sign-in attempt; one it cannot answer does not. `UpstreamGrant::with_subject` names the person, say by the provider's user id, so their subject stays the same across sign-ins; without it, the subject is derived from the credential. Tools receive the credential as a `Credential` and exchange it for access tokens as they need them; a provider that rotates refresh tokens on every use cannot be used this way, because the sealed credential never changes.

### Single sign-on and many named users

The modes are deliberately few. For single sign-on, multi-factor authentication or many named users, put an identity-aware gateway such as Cloudflare Access or oauth2-proxy in front of `/authorize`. It is the only page a person's browser opens.

## The CredentialVerifier trait

A [`CredentialVerifier`](https://docs.rs/mcp-server-core/latest/mcp_server_core/credential/trait.CredentialVerifier.html) decides what the sign-in page asks for and checks it. The server asks it when someone submits the sign-in page and, when it accepts bearer credentials, for bearer tokens that are not this server's own tokens.

| Method | Default | What it does |
|---|---|---|
| `label(&self) -> &str` | required | The credential's name in lower case, as it reads in a sentence: `password`, `Companies House API key`. It names the field and appears in messages. It is also part of the sign-in version, so changing it signs everyone out. |
| `help(&self) -> &str` | `""` | One sentence of plain-text help under the field: what the credential is and where to get one. |
| `prepare(&self, entered) -> &str` | trims surrounding whitespace | Turns what was typed, or sent as a bearer token, into the credential to check. Pasted keys often carry spaces; `PasswordVerifier` keeps them. |
| `plausible(&self, credential) -> bool` | [`credential::plausible`](https://docs.rs/mcp-server-core/latest/mcp_server_core/credential/fn.plausible.html) | Whether the input has the shape of a credential. Implausible input is refused locally: it is never sent upstream and does not count as a failed attempt. |
| `check(&self, credential) -> CheckFuture` | required | Checks the credential, typically with one cheap authenticated request upstream. |
| `carried(&self) -> bool` | `true` | Whether the credential is the person's own key to the upstream service: sealed into their tokens and handed to tools. `false` for a password that only proves who may sign in. |
| `accepts_bearer(&self) -> bool` | `carried()` | Whether a client may send the credential itself as its bearer token instead of signing in with OAuth. |
| `subject(&self, credential) -> Option<String>` | `None` | Who signed in, as tokens, logs and the audit log name them. `None` lets the server name them (see [Subjects](#subjects)). It must not reveal the credential. |
| `generation(&self) -> &[u8]` | empty | Bytes that change whenever every earlier sign-in should end, such as a hash of a password or the upstream environment. They go into the sign-in version with the label. |
| `upstream(&self) -> Option<&dyn UpstreamSignIn>` | `None` | An upstream OAuth provider people sign in through instead of typing a credential. See [Signing in through an upstream provider](#signing-in-through-an-upstream-provider). |

The default `plausible` accepts 1 to 256 bytes ([`credential::MAX_CREDENTIAL_LEN`](https://docs.rs/mcp-server-core/latest/mcp_server_core/credential/constant.MAX_CREDENTIAL_LEN.html)) of visible ASCII without spaces. Narrow it when the upstream service's credentials have a known form, so other tokens are refused without asking upstream:

```rust
use mcp_server_core::credential::{CheckFuture, CredentialCheck, CredentialVerifier};
# async fn whoami(_key: &str) -> Result<bool, String> { Ok(true) }

/// Keys for the Example API: `ex_` and 32 letters or digits.
struct ExampleKeys;

impl CredentialVerifier for ExampleKeys {
    fn label(&self) -> &str {
        "Example API key"
    }

    fn help(&self) -> &str {
        "Create one under Settings, API keys at example.com."
    }

    fn plausible(&self, key: &str) -> bool {
        key.len() == 35
            && key.starts_with("ex_")
            && key[3..].bytes().all(|b| b.is_ascii_alphanumeric())
    }

    fn check<'a>(&'a self, key: &'a str) -> CheckFuture<'a> {
        Box::pin(async move {
            // For example GET /v1/me with the key: 200, 401, or the API is down.
            match whoami(key).await {
                Ok(true) => CredentialCheck::Valid,
                Ok(false) => CredentialCheck::Invalid(None),
                Err(why) => CredentialCheck::Unavailable(why),
            }
        })
    }
}
#
# assert!(ExampleKeys.plausible("ex_0123456789abcdef0123456789abcdef"));
# assert!(!ExampleKeys.plausible("ghp_0123456789abcdef0123456789abcdef"));
```

The [`api_keys` example](examples.md) is a complete server built this way.

### Verdicts

`check` returns a [`CredentialCheck`](https://docs.rs/mcp-server-core/latest/mcp_server_core/credential/enum.CredentialCheck.html):

| Verdict | Meaning | On the sign-in page | On a bearer request | Counts as a failed attempt |
|---|---|---|---|---|
| `Valid` | Accepted. | Signs the person in. | Lets the request through. | No |
| `Invalid(reason)` | Rejected. `reason` is shown when it is more useful than the default. | 401 with the reason, or `That <label> was not accepted.` | 401 | Yes |
| `Unavailable(why)` | Could not be checked now: upstream down or rate limited. | 503 with `Your <label> could not be checked right now: <why>` | 503 with the same text | No |

Both 503 answers carry `Retry-After: 30`. On a bearer request, `Valid` and `Invalid` verdicts are remembered for a while and `Unavailable` is not; how long is on [Limits and abuse protection](limits.md).

Input refused by `plausible` gets a 401 and `That is not a <label>.` on the sign-in page, and a 401 on a bearer request. `CredentialCheck` is `#[non_exhaustive]`.

Checks run with a timeout, with a cap on how many run at once, and once at a time per credential: requests that arrive while a credential is being checked share that check. A check that times out is `Unavailable("the check timed out")`, and one that cannot get a slot is `Unavailable("the server is checking too many credentials at once")`. The numbers, and how attempts count towards the sign-in limits, are on [Limits and abuse protection](limits.md).

### PasswordVerifier

`PasswordVerifier::new(password)` takes a `secrecy::SecretString`, which `.into()` makes from a `String`, and accepts exactly that password, compared in constant time. It is what `SignIn::OwnerPassword` builds, and you can build one yourself in a `SignIn::Custom` function. Its behaviour differs from the defaults:

| Method | `PasswordVerifier` |
|---|---|
| `label` | `password` |
| `prepare` | Keeps the input as typed. |
| `plausible` | Non-empty and at most 1,024 bytes. |
| `carried` | `false`, so `accepts_bearer` is `false` too. |
| `generation` | A SHA-256 hash of the password, so a new password ends every earlier grant. |

It keeps the defaults for `help` (none) and `subject` (`None`, so the server names the person `owner`). Its `Debug` output is `PasswordVerifier(..)`.

## Sealed credentials

With a carried credential the server stores nothing. The credential is checked once, then sealed into the person's tokens by a [`Sealer`](https://docs.rs/mcp-server-core/latest/mcp_server_core/credential/struct.Sealer.html):

- **Cipher**: ChaCha20-Poly1305, with a fresh random nonce for every seal.
- **Key**: derived from `OAUTH_SIGNING_KEY` with HKDF-SHA256, so whoever holds the signing key can open every sealed credential. Keep it secret.
- **Where**: the `credential` claim of the authorization code, the access token and the refresh token. Anyone holding a token can read its claims, but not the sealed credential.
- **Rotation**: changing `OAUTH_SIGNING_KEY` makes every sealed credential unreadable, along with every token.

On each request the bearer guard opens the sealed credential and adds it to the request as a `Credential`. An access token whose credential does not open is refused with 401. At the token endpoint, a code or refresh token whose credential is missing or does not open gets `invalid_grant` with `grant has no credential`.

A sealed value is `base64url(nonce || ciphertext || tag)`. `Sealer::new(signing_key)`, `seal(&str)` and `open(&str)` are public, for tests and lower-level servers; `seal` and `open` fail with a [`SealError`](https://docs.rs/mcp-server-core/latest/mcp_server_core/credential/enum.SealError.html) (`sealing failed`, or `the sealed credential is invalid`). [`AuthState::sealer`](https://docs.rs/mcp-server-core/latest/mcp_server_core/oauth/struct.AuthState.html#method.sealer) returns the server's own.

A password that is not carried, such as the owner's, never enters a token: it only decides whether the code is issued.

### Reading the credential in a tool

A tool takes rmcp's `Extension<Parts>` argument and reads the `Credential` from the request extensions:

```rust
use mcp_server_core::rmcp;
use mcp_server_core::axum::http::request::Parts;
use mcp_server_core::credential::Credential;
use mcp_server_core::rmcp::handler::server::router::tool::ToolRouter;
use mcp_server_core::rmcp::handler::server::tool::Extension;
use mcp_server_core::rmcp::model::{CallToolResult, ContentBlock, ServerCapabilities, ServerConfig};
use mcp_server_core::rmcp::{ErrorData as McpError, ServerHandler, tool, tool_handler, tool_router};

#[derive(Clone)]
struct AccountTools {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl AccountTools {
    fn new() -> Self {
        Self { tool_router: Self::tool_router() }
    }

    #[tool(description = "Show which key this connection uses.", annotations(read_only_hint = true))]
    async fn whoami(&self, Extension(parts): Extension<Parts>) -> Result<CallToolResult, McpError> {
        let Some(key) = parts.extensions.get::<Credential>() else {
            return Ok(CallToolResult::error(vec![ContentBlock::text("unauthenticated: no key")]));
        };
        // Send key.expose() upstream. Never log it.
        let shown = &key.expose()[key.expose().len().saturating_sub(4)..];
        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "You are using the key ending {shown}."
        ))]))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for AccountTools {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
    }
}
# fn main() { let _ = AccountTools::new(); }
```

| `Credential` item | Returns |
|---|---|
| `Credential::new(secret)` | A credential wrapping `secret`, for tests or middleware of your own. |
| `expose()` | The secret, to send upstream. Never log it. |
| `fingerprint()` | Its SHA-256 as `[u8; 32]`, safe as a map key, for example to keep one upstream client per person. Not for logs. [`credential::fingerprint(&str)`](https://docs.rs/mcp-server-core/latest/mcp_server_core/credential/fn.fingerprint.html) computes the same for any string. |

Its `Debug` output is `Credential(..)`, so the secret cannot leak through a stray `{:?}`. A request has a `Credential` only when the verifier carries credentials. Requests made with the owner's password or the static token have none.

## Credentials sent as bearer tokens

When the verifier's `accepts_bearer()` is `true` (the default for carried credentials), a client may skip OAuth and send the credential itself:

```http
POST /example HTTP/1.1
Host: mcp.example.com
Authorization: Bearer ex_0123456789abcdef0123456789abcdef
```

The bearer guard works through a token in this order:

1. **This server's own token.** A token shaped like a JWT is verified as an access token for the path. If it is not one but names this server as its issuer, for example an expired token or one for another service, it is refused with 401. This server's tokens are never sent upstream and never count as failed attempts. When the verifier does not accept bearer credentials, every other token shaped like a JWT is refused the same way.
2. **The static token**, when `MCP_AUTH_TOKEN` is set (never alongside a verifier that accepts bearer credentials).
3. **The person's credential.** The guard applies `prepare` and `plausible`, then looks the credential up in a short cache of recent verdicts, keyed by its SHA-256. On a miss it runs `check`. The attempt counts towards the sign-in limits while the check runs, and afterwards only if the credential was rejected.

A valid credential gets a `Caller` with `Via::Credential` and, when the verifier carries credentials, the same `Credential` extension as an OAuth token. Any other answer is a 401, except `Unavailable`, which is a 503, and a refusal by the sign-in limits, which is a 429 (or a 503 while the server refuses new addresses under heavy load). A credential that has the shape of a JWT but was not issued here is checked as a credential. A credential found valid recently is let in even from an address that is blocked for too many failures: its holder has already proved possession.

To allow OAuth only, override `accepts_bearer` to return `false`.

## The static token

`MCP_AUTH_TOKEN` is a fixed bearer token for clients that can send a header, such as Claude Code. It is accepted on every service path and on `/mcp`.

```sh
MCP_AUTH_TOKEN=$(openssl rand -hex 32)
```

| Rule | Error or warning |
|---|---|
| Only when sign-in does not carry credentials and does not accept them as bearer tokens. Requests made with it would lack the credential tools expect, and wrong tokens could be tried upstream as credentials. | `MCP_AUTH_TOKEN cannot be used when people sign in with their own <label>` |
| Must not have the shape of a JWT: exactly two dots. | `MCP_AUTH_TOKEN must not have the shape of a JWT (three dot-separated parts)` |
| Should be at least 32 characters ([`app::RECOMMENDED_STATIC_TOKEN_CHARS`](https://docs.rs/mcp-server-core/latest/mcp_server_core/app/constant.RECOMMENDED_STATIC_TOKEN_CHARS.html)). | Warning: `MCP_AUTH_TOKEN is shorter than 32 characters: use a long random value` |

Both errors stop the server at startup, listed with the other configuration errors. They are checked only once the core settings, such as `PUBLIC_URL` and `OAUTH_SIGNING_KEY`, are valid, and the first only once the verifier has been built. [`AuthState::new`](https://docs.rs/mcp-server-core/latest/mcp_server_core/oauth/struct.AuthState.html#method.new) panics with the same messages if you build a server without `app::Server`.

How it behaves:

- It is compared in constant time.
- Every bearer token that does not have the shape of a JWT counts towards the [sign-in limits](limits.md) before it is compared, which bounds how fast anyone can guess the static token. A blocked address cannot use even the right token until the limit clears; OAuth tokens already issued keep working. Tokens shaped like a JWT cannot be the static token and are refused without counting.
- Requests made with it have the subject `static`, no `Credential` and no OAuth claims. The audit log records them as caller `static`.
- It is not part of the sign-in version: changing it does not end OAuth grants, and changing `OAUTH_ADMIN_PASSWORD` does not change it.

Treat it like the owner's password. Leave it unset if every client signs in with OAuth: then, on an owner's-password server, bearer tokens that are not this server's are refused without counting, so junk cannot lock anyone out.

## Who made a request

The bearer guard adds a [`caller::Caller`](https://docs.rs/mcp-server-core/latest/mcp_server_core/caller/struct.Caller.html) to every request it lets through. It has two fields:

- `subject`: who signed in.
- `via`: how the request was authenticated, a [`Via`](https://docs.rs/mcp-server-core/latest/mcp_server_core/caller/enum.Via.html).

| `Via` | Meaning | Audit log `caller` |
|---|---|---|
| `OAuth { client_id }` | An access token this server issued, to this client. | `oauth:<client_id>`, or `oauth` without a client id |
| `Credential` | The person's credential sent as the bearer token. | `credential` |
| `StaticToken` | `MCP_AUTH_TOKEN`. | `static` |

`Caller::audit_label()` returns the audit log's form. A request with an OAuth token also carries the token's [`jwt::Claims`](https://docs.rs/mcp-server-core/latest/mcp_server_core/jwt/struct.Claims.html). Both `Caller` and `Via` are `#[non_exhaustive]`; `Caller::new` builds one for your own middleware or tests.

### Subjects

| Subject | When |
|---|---|
| `owner` | The owner's password, or any verifier that does not carry credentials and names no subject. |
| `key:` and 16 hex digits | A carried credential, when the verifier names no subject. The digits are a hash of the credential keyed by `OAUTH_SIGNING_KEY`, so the subject identifies one person without letting anyone who sees it guess the credential offline. Rotating the key changes every such subject. |
| `static` | The static token. |
| anything else | What your verifier's `subject()` returns. |

The subject is the `sub` claim of the person's code, access and refresh tokens, and it is kept through refreshes. Logs and the audit log use it, never the credential. [`AuthState::subject_of`](https://docs.rs/mcp-server-core/latest/mcp_server_core/oauth/struct.AuthState.html#method.subject_of) returns the subject the server gives a credential.

Reading it in a tool, for example to attribute a change:

```rust
use mcp_server_core::axum::http::request::Parts;
use mcp_server_core::caller::{Caller, Via};

fn changed_by(parts: &Parts) -> String {
    let Some(caller) = parts.extensions.get::<Caller>() else {
        return "unknown".into();
    };
    let how = match &caller.via {
        Via::OAuth { client_id: Some(id) } => format!("OAuth client {id}"),
        Via::OAuth { client_id: None } => "OAuth".into(),
        Via::Credential => "their own key".into(),
        Via::StaticToken => "the static token".into(),
        _ => "another way".into(),
    };
    format!("{} via {how}", caller.subject)
}

let (mut parts, ()) = mcp_server_core::axum::http::Request::new(()).into_parts();
parts.extensions.insert(Caller::new("owner", Via::OAuth { client_id: Some("c1".into()) }));
assert_eq!(changed_by(&parts), "owner via OAuth client c1");
```

The OAuth client id is a long signed token; record it only where its length does not matter.

Next: [OAuth and tokens](oauth.md).
