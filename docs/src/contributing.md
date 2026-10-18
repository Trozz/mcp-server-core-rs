# Contributing

Bug reports, questions and pull requests are all welcome. This page explains how to report a problem, set up the repository, run the checks CI runs, try a change against a real client, build this site and send a pull request. The repository's [CONTRIBUTING.md](https://github.com/Trozz/mcp-server-core-rs/blob/main/CONTRIBUTING.md) is the short version.

## Reporting problems

- **Security problems**: do not open an issue. Report them privately, as described under [Reporting a vulnerability](security.md#reporting-a-vulnerability).
- **Bugs**: open an [issue](https://github.com/Trozz/mcp-server-core-rs/issues) with what you did, what you expected and what happened, the crate and Rust versions, and logs with secrets removed.
- **Ideas**: open an issue before a large change, so the shape can be agreed first.

## Setting up

```sh
git clone https://github.com/Trozz/mcp-server-core-rs
cd mcp-server-core-rs
cargo test --all-features
```

The toolchain is pinned in `rust-toolchain.toml` to Rust 1.99.1 with `rustfmt` and `clippy`; `rustup` installs it the first time you run `cargo` in the repository. The crate itself supports Rust 1.88 and later; see [Minimum supported Rust version](releases.md#minimum-supported-rust-version).

You also need:

- `openssl`, or another source of random bytes, to make a signing key when running the examples;
- [cargo-deny](https://github.com/EmbarkStudios/cargo-deny) for `cargo deny check` (`cargo install --locked cargo-deny`);
- the documentation tools, only to build this site; see [Building this site](#building-this-site).

## Checks

Run these before opening a pull request:

```sh
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --all-targets --no-default-features -- -D warnings
cargo test --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo deny check
```

`cargo test --all-features` runs the unit tests, the integration tests in `tests/` and every doctest: the examples in the API documentation, the README and this site.

### What CI runs

The `ci` workflow ([`.github/workflows/ci.yml`](https://github.com/Trozz/mcp-server-core-rs/blob/main/.github/workflows/ci.yml)) runs on every pull request and every push to `main`. A newer push to the same pull request cancels the run in progress.

| Job | Runs on | Command |
|---|---|---|
| `fmt` | Ubuntu 24.04 | `cargo fmt --all --check` |
| `clippy (--all-features)`, `clippy (--no-default-features)` | Ubuntu 24.04 | `cargo clippy --all-targets --locked <features> -- -D warnings` |
| `test (ubuntu-24.04)`, `test (macos-15)` | Ubuntu 24.04 and macOS 15 | `cargo test --all-features --locked` |
| `build (windows)` | Windows Server 2025 | `cargo build --all-targets --all-features --locked` |
| `msrv` | Ubuntu 24.04 | Installs the Rust version in `rust-version`, then `cargo check --lib --locked` on it (`RUSTUP_TOOLCHAIN`) with every feature and with none |
| `docs` | Ubuntu 24.04 | `cargo doc --no-deps --all-features --locked` with `RUSTDOCFLAGS=-D warnings` |
| `book` | Ubuntu 24.04 | `scripts/install-docs-tools.sh`, then `scripts/build-docs.sh` |
| `cargo-deny` | Ubuntu 24.04 | `cargo deny check` |
| `package` | Ubuntu 24.04 | `cargo package --locked` |

The other jobs that compile the crate install the pinned Rust 1.99.1. Inside the repository `rust-toolchain.toml` takes precedence over rustup's default toolchain, so the `msrv` job names its toolchain with `RUSTUP_TOOLCHAIN`; to check the library on the minimum supported version yourself, name the toolchain, as [Minimum supported Rust version](releases.md#minimum-supported-rust-version) shows. `--locked` means `Cargo.lock` must be up to date: commit it with any dependency change.

### Lints

`Cargo.toml` sets the crate's lints, and `-D warnings` turns every warning into an error in CI:

| Lint | Level | Effect |
|---|---|---|
| `unsafe_code` | `forbid` | No `unsafe` anywhere. |
| `missing_docs` | `warn` | Every public item needs a doc comment. |
| `clippy::dbg_macro` | `warn` | No `dbg!` left behind. |
| `clippy::todo` | `warn` | No `todo!` left behind. |
| `unexpected_cfgs` | `warn` | Only known `cfg` names; `docsrs`, which docs.rs sets, is declared. |

### cargo-deny

`deny.toml` checks every dependency, with all features on:

- **Advisories**: known vulnerabilities and yanked crates fail the check. One advisory is ignored, `RUSTSEC-2023-0071` in `rsa`, which `jsonwebtoken` pulls in although only HS256 is used, with the reason written next to it.
- **Licences**: only MIT, Apache-2.0 (also with the LLVM exception), BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, Zlib, CDLA-Permissive-2.0, 0BSD and MPL-2.0.
- **Bans**: `openssl`, `openssl-sys`, `native-tls`, `aws-lc-rs` and `aws-lc-sys`. TLS is rustls with the `ring` provider throughout.
- **Sources**: crates.io only; no git dependencies.

## Tests

Unit tests sit next to the code in `src/`. The integration tests in `tests/` drive the HTTP application in memory, without a network, except for TLS:

| File | Covers |
|---|---|
| `abuse_limits.rs` | Limits on bearer credentials: per-address, per-block and global failure limits, shared checks |
| `app_e2e.rs` | A whole server built with `app::Server` from environment variables, as `main` would build it |
| `docs_consistency.rs` | The configuration reference against the variables the server reads |
| `hardening.rs` | Grants ending when the sign-in changes or grows old, tokens not crossing sign-in modes, registration caps, the issuer and security headers |
| `oauth_authorize.rs` | The sign-in page and `POST /authorize`, for both kinds of sign-in |
| `oauth_flow.rs` | The bearer guard in front of services, and the whole OAuth flow end to end |
| `oauth_metadata.rs` | Authorization-server and protected-resource metadata, and client registration |
| `oauth_token.rs` | The token endpoint: code exchange and refresh |
| `prompts_e2e.rs` | Prompts on a service's own endpoint and on the combined endpoint |
| `service_mount.rs` | Host and Origin checks of a mounted MCP service |
| `session_binding.rs` | MCP sessions bound to the credential that opened them |
| `tls_serve.rs` | Serving over TLS and plain HTTP, and the healthcheck |
| `tool_policy.rs` | The read-only rule and the audit log, through the same HTTP stack the binary serves |

`tests/oauth_support/mod.rs` holds what the OAuth tests share: a `TestVerifier` that accepts listed credentials and counts its checks, and constants such as the public URL, password and keys. Run one file with `cargo test --all-features --test oauth_flow`.

## Running the examples

To try a change against a real MCP client, run an example. The owner's-password server:

```sh
PUBLIC_URL=http://localhost:8443 INSECURE_HTTP=true \
OAUTH_SIGNING_KEY=$(openssl rand -hex 32) OAUTH_ADMIN_PASSWORD='a long password' \
LOG_FORMAT=pretty cargo run --example notes
```

The server where each person signs in with their own key:

```sh
PUBLIC_URL=http://localhost:8443 INSECURE_HTTP=true \
OAUTH_SIGNING_KEY=$(openssl rand -hex 32) LOG_FORMAT=pretty \
cargo run --example api_keys
```

Then connect a client, or `npx @modelcontextprotocol/inspector`, to `http://localhost:8443/notes` or `http://localhost:8443/account`. [Examples](examples.md) describes what each shows and what to try.

## Building this site

The site is an [mdBook](https://rust-lang.github.io/mdBook/) in `docs/`:

| Path | Holds |
|---|---|
| `docs/book.toml` | The book's settings, including the `mdbook-mermaid` preprocessor. `create-missing = false`, so every page listed in the summary must exist. |
| `docs/src/SUMMARY.md` | The table of contents: every page, in order. |
| `docs/src/*.md` | The pages. |
| `docs/theme/` | The favicon. |
| `docs/book/` | The built site (not committed). |

### Tools

The tools are pinned: mdBook 0.5.4, mdbook-mermaid 0.17.1 and lychee 0.24.2. On Linux x86_64, as CI does, install them into a directory on your `PATH`; the script downloads the release archives and checks their SHA-256 sums:

```sh
bash scripts/install-docs-tools.sh "$HOME/.local/bin"
```

On other platforms, build them with Cargo:

```sh
cargo install --locked mdbook@0.5.4 mdbook-mermaid@0.17.1 lychee@0.24.2
```

### Building and previewing

```sh
bash scripts/build-docs.sh
mdbook serve docs --open
```

`scripts/build-docs.sh` installs mdbook-mermaid's scripts into `docs/` (`mermaid.min.js` and `mermaid-init.js`, which are not committed), builds the site into `docs/book`, then runs lychee offline over the built pages to check every internal link and anchor. External links are not checked. Run it before `mdbook serve` the first time, so the diagrams render.

### Rust examples are tests

Every page is compiled as rustdoc doctests. `src/lib.rs` includes each page under `#[cfg(doctest)]` in a module `book`, one struct per page named after its file in CamelCase:

```rust,ignore
#[cfg(doctest)]
mod book {
    #[doc = include_str!("../docs/src/quick-start.md")]
    struct QuickStart;
    // ... one struct for every page
}
```

`cargo test --all-features` runs them with the other tests. To check one page while you edit it:

```sh
cargo test --doc --all-features book::QuickStart
```

So that pages read well in mdBook and still compile:

- Give every fenced code block a language: `rust`, `sh`, `toml`, `json`, `yaml`, `nginx`, `dockerfile`, `http`, `text` or `mermaid`. rustdoc treats a block without one as Rust and fails on it.
- Never indent code by four spaces to make a code block: rustdoc compiles those too.
- Use `rust,no_run` for code that would start a server or reach the network: it is compiled but not run.
- Hide setup with lines starting `# `. mdBook hides them from readers, and rustdoc still compiles them.
- Use `rust,ignore` only for a deliberate fragment that cannot compile on its own, as above.
- Adapt code that already compiles, from the README, the API documentation or `examples/`, where you can.

### Adding a page

1. Create `docs/src/<name>.md`, starting with `# ` and its title.
2. List it in `docs/src/SUMMARY.md`.
3. Add a struct for it to `mod book` in `src/lib.rs`, so its examples are tested.

A new environment variable belongs in the [configuration reference](configuration.md). `tests/docs_consistency.rs` records every variable `Server::load` reads and fails until the reference has a table row for it, with its name in backticks in the first column (prefixed ones written as `<PREFIX>_SERVICES` and so on). It fails too if the reference names a variable the server does not read.

`Cargo.toml` lists `docs/src/**/*.md` under `include`, so the pages ship in the crate package with `src/lib.rs`, which includes them.

### Writing style

The site is written in British English, in the present tense and the second person, in short sentences. Each topic has one page; other pages link to it rather than repeat it. Numbers, defaults, variable names and error messages are copied from the code, and an error message is quoted exactly.

## Guidelines

- Keep the public API small and documented. Every public item needs a doc comment, and examples in the API documentation, the README and this site are compiled as tests.
- Security-relevant behaviour (sign-in, tokens, limits, logging) needs a test that would fail without the change.
- Never log secrets, credentials, session ids or content. Content may be logged only when [`observability::content_logging_enabled()`](https://docs.rs/mcp-server-core/latest/mcp_server_core/observability/fn.content_logging_enabled.html) is true.
- No `unsafe` code.
- Add an entry to `CHANGELOG.md` under `## [Unreleased]`.
- Write commit messages in the [Conventional Commits](https://www.conventionalcommits.org/) style, such as `fix: count wrong static tokens towards the sign-in limit`.

## Pull requests

Open pull requests against `main`. CI must pass. Releases are tagged from `main`, as [Releases and versioning](releases.md#the-release-process) describes.

## Licence

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as defined in the Apache-2.0 licence, shall be dual licensed under the MIT and Apache-2.0 licences, without any additional terms or conditions.
