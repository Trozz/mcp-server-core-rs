# Introduction

mcp-server-core is a Rust crate for building [Model Context Protocol](https://modelcontextprotocol.io) (MCP) servers that clients such as claude.ai, Claude Desktop and Claude Code reach over the internet. You write the tools; the crate serves them over Streamable HTTP with sign-in, TLS and the protections a server shared by many people needs.

It is built on [rmcp](https://crates.io/crates/rmcp), the official Rust SDK for MCP, and re-exports it, so your tools are ordinary rmcp tools.

| | |
|---|---|
| Crate | [crates.io/crates/mcp-server-core](https://crates.io/crates/mcp-server-core) |
| API documentation | [docs.rs/mcp-server-core](https://docs.rs/mcp-server-core) |
| Source | [github.com/Trozz/mcp-server-core-rs](https://github.com/Trozz/mcp-server-core-rs) |
| Licence | MIT or Apache-2.0, at your option |

## Who it is for

You have, or want to write, MCP tools in Rust: a wrapper around an API, your own data, a device on your network. You want claude.ai or another hosted client to use them, which means a public HTTPS endpoint that signs people in with OAuth. That part is where the risk lies: an MCP server on the internet acts on someone's behalf, and anyone can reach its sign-in page.

This crate is that part, extracted from the [two servers](#who-uses-it) built on it, which each carried a copy of the code. It suits:

- **A personal server**: one person, the owner, signs in with a password, and the tools use the server's own access to an upstream service, such as an app password in the environment.
- **A shared server**: many people each sign in with their own key for the upstream API, and the tools act with that person's key. The server stores no keys.

## What you write and what you get

| You write | The crate gives you |
|---|---|
| Your tools, as an rmcp handler with `#[tool]` methods, each marked read-only or not | Streamable HTTP serving, a new handler for each MCP session, and, when people sign in with their own credentials, sessions bound to the credential that opened them |
| A [`Service`](writing-a-service.md#the-service-trait): a name and the handler | The service at `/<name>`, its own OAuth protected resource, and its tools on the combined `/mcp` endpoint |
| A factory that reads your service's settings | The server's own settings, `_FILE` variants for secrets, and every configuration error reported at once |
| Optionally, a check of a person's upstream credential | The sign-in page, OAuth 2.1, sealed credentials handed to your tools, and limits on guessing |
| `main`: a `Server` with your services | `--version`, `--help`, `--healthcheck`, TLS, logs, metrics, traces and graceful shutdown |

The smallest server is about sixty lines; see the [quick start](quick-start.md).

## Features

- **OAuth 2.1 built in**: dynamic client registration, PKCE (S256), resource indicators (RFC 8707) and protected-resource metadata (RFC 9728). Every token is a signed JWT, so there is no database, and restarts and extra replicas sign nobody out. See [OAuth and tokens](oauth.md).
- **Two ways to sign in**: the owner's password, or each person's own credential for the upstream service, checked when they sign in and sealed into their tokens. You can also supply your own check. See [Sign-in modes](sign-in.md).
- **Several services on one server**, each at `/<name>` and each its own OAuth resource, plus all of their tools and prompts together at `/mcp` as `<service>_<tool>`. See [Several services and /mcp](combined.md) and [Prompts](prompts.md).
- **Read-only mode and an audit log** for every service, from each tool's `read_only_hint`. See [Read-only mode and the audit log](read-only-and-audit.md).
- **Abuse limits**: sign-in attempts limited per address, per network block and overall, capped and shared upstream credential checks, capped client registration, sessions capped per credential, body limits. See [Limits and abuse protection](limits.md).
- **Ready to deploy**: TLS from certificate files (reloaded when they change), a self-signed certificate, or plain HTTP behind a proxy; Host and Origin checks against DNS rebinding; a container healthcheck; graceful shutdown. See [TLS and deployment](deployment.md).
- **Observability**: JSON logs that keep secrets and content out, Prometheus metrics and OpenTelemetry traces. See [Observability](observability.md).
- **Configured by environment variables**, with `_FILE` variants for secrets and every error reported at once. See the [configuration reference](configuration.md).

## How people sign in

You choose one sign-in mode for the whole server with `Server::sign_in`:

| Mode | Who signs in | What your tools get |
|---|---|---|
| `SignIn::OwnerPassword` (the default) | One person, with `OAUTH_ADMIN_PASSWORD`. A static bearer token, `MCP_AUTH_TOKEN`, can be set as well for clients that cannot do OAuth. | Nothing about the person: tools act with the server's own upstream configuration. |
| `SignIn::ServiceCredential` | Anyone with a credential the upstream service accepts, such as an API key, checked by your service's verifier. | The person's credential, sealed inside their tokens and handed to tools on every request. Clients may also send the credential itself as their bearer token. |
| `SignIn::Custom(..)` | Whoever your own verifier accepts. | Either, depending on the verifier. |

Every request a tool receives also says who signed in and how. [Sign-in modes](sign-in.md) covers all of this; for single sign-on, MFA or many named users, it explains how to put an identity-aware gateway in front of the sign-in page instead.

## Who uses it

Two open-source servers are built on mcp-server-core, one for each sign-in model:

| Server | What it does | Sign-in |
|---|---|---|
| [mcp-icloud](https://github.com/Trozz/mcp-icloud) | iCloud mail, calendars and contacts, as services `/mail`, `/calendar` and `/contacts` | The owner's password; the server holds the owner's app-specific password for Apple |
| [mcp-companies-house](https://github.com/Trozz/mcp-companies-house) | The UK Companies House register: companies, officers, owners, filings and charges | Each person's own Companies House API key; the server holds none |

Both are larger examples of what this site describes. The repository's own [examples](examples.md) are small versions of the same two shapes.

## How this site is organised

| Section | Pages |
|---|---|
| Getting started | [Quick start](quick-start.md), [Writing a service](writing-a-service.md), [Several services and /mcp](combined.md), [Prompts](prompts.md), [Examples](examples.md) |
| Signing people in | [Sign-in modes](sign-in.md), [OAuth and tokens](oauth.md), [Connecting clients](connecting-clients.md) |
| Running a server | [Configuration reference](configuration.md), [TLS and deployment](deployment.md), [Read-only mode and the audit log](read-only-and-audit.md), [Observability](observability.md), [Troubleshooting](troubleshooting.md) |
| Security | [Security model](security.md), [Limits and abuse protection](limits.md) |
| Reference | [Endpoints](endpoints.md), [Lower-level API](lower-level-api.md), [Changelog](changelog.md) |
| Project | [Architecture](architecture.md), [Contributing](contributing.md), [Releases and versioning](releases.md) |

If you are new, read the quick start, then Writing a service. If you are deploying a server someone else wrote, start at the configuration reference and TLS and deployment. The [API documentation on docs.rs](https://docs.rs/mcp-server-core) has every public item; this site explains how they fit together.

## Requirements

- Rust 1.88 or later.
- A Tokio runtime: `Server::main` is `async`.
- rmcp through the re-export `mcp_server_core::rmcp`, with `use mcp_server_core::rmcp;` in each file that uses its macros (see the [quick start](quick-start.md#add-the-crate)). Its types appear in this crate's API, so this crate follows rmcp's minor versions; see [Releases and versioning](releases.md).

## Licence

mcp-server-core is licensed under either of the [Apache License, Version 2.0](https://github.com/Trozz/mcp-server-core-rs/blob/main/LICENSE-APACHE) or the [MIT licence](https://github.com/Trozz/mcp-server-core-rs/blob/main/LICENSE-MIT), at your option. Unless you state otherwise, any contribution you submit for inclusion is dual licensed in the same way, without any additional terms or conditions.
