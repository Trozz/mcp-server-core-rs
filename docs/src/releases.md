# Releases and versioning

This page explains what the crate's version numbers promise, which Rust versions it supports, how a release is made and published, how this site is published, and which versions receive fixes. What changed in each version is in the [changelog](changelog.md).

## Versioning

mcp-server-core follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html), and its changelog follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

| Version change | Before 1.0 | Example |
|---|---|---|
| Minor | May change the API | 0.1.0 to 0.2.0 |
| Patch | Does not change the API in a way that breaks your code | 0.1.0 to 0.1.1 |

From 1.0, only a major version may break the API. Until then, depend on a minor version and read the changelog before moving to the next:

```toml
[dependencies]
mcp-server-core = "0.3"
```

Cargo reads `"0.3"` as `>=0.3.0, <0.4.0`: you get patch releases with `cargo update`, and never a new minor version without changing the requirement.

An upgrade can affect a running server as well as your code. The 0.1.0 entry, for example, says that tokens issued by the servers' earlier copies of this code lack the new claims, so everyone signs in once more after upgrading. Read the **Changed** section before upgrading a deployed server.

[Lower-level API](lower-level-api.md#stability-and-semver) lists the `#[non_exhaustive]` types, which later versions can extend without a breaking change.

### rmcp and axum

The crate's API includes types from [rmcp](https://crates.io/crates/rmcp) and [axum](https://crates.io/crates/axum), re-exported as `mcp_server_core::rmcp` and `mcp_server_core::axum`. Their versions are part of this crate's compatibility:

| Dependency | Requirement in `Cargo.toml` | Accepts |
|---|---|---|
| rmcp | `~3.8.0` | 3.8.0 and later 3.8 patch releases, never 3.9 |
| axum | `0.8.9` | 0.8.9 and later 0.8 releases, never 0.9 |

rmcp is held to one minor version on purpose. The [policy wrapper](read-only-and-audit.md#the-policy-module) forwards every method of rmcp's `ServerHandler` trait to your handler, so a new rmcp minor version, which may add or change methods, needs a release of this crate that forwards them too. This crate therefore follows rmcp's minor versions: moving to a new one is a new minor version here. Use rmcp through the re-export rather than adding it to your own `Cargo.toml`, so the versions always match.

## Minimum supported Rust version

The minimum supported Rust version (MSRV) is **1.88**, set as `rust-version` in `Cargo.toml`. The crate uses the 2024 edition, which needs Rust 1.85, and let chains (`if let ... && let ...`), which need Rust 1.88.

The `msrv` CI job runs on every pull request and every push to `main`. It reads `rust-version` from `Cargo.toml`, installs that toolchain and runs, with `RUSTUP_TOOLCHAIN` set to it:

```sh
cargo check --lib --all-features --locked
cargo check --lib --no-default-features --locked
```

Inside the repository, `rust-toolchain.toml` pins Rust 1.99.1 and takes precedence over rustup's default toolchain, which is why the job sets `RUSTUP_TOOLCHAIN`. To check the library on the minimum supported version yourself, name the toolchain, which also takes precedence over the file:

```sh
rustup toolchain install 1.88
cargo +1.88 check --lib --all-features --locked
cargo +1.88 check --lib --no-default-features --locked
```

Only the library is meant to build at the MSRV. Tests, examples and the development tools use the toolchain pinned in `rust-toolchain.toml`, currently Rust 1.99.1, which `rustup` installs when you build in the repository.

## Supported versions

Until 1.0, only the latest minor version receives security fixes. Fixes are released as patch versions and announced in a GitHub security advisory once a fixed version is available.

| Version | Supported |
|---|---|
| 0.1.x | Yes |

To report a vulnerability, see [Security model](security.md#reporting-a-vulnerability).

## The release process

A release is a version bump merged to `main`. The steps, from the repository's [CONTRIBUTING.md](https://github.com/Trozz/mcp-server-core-rs/blob/main/CONTRIBUTING.md#releasing):

1. Move the entries under `## [Unreleased]` in `CHANGELOG.md` to a new heading `## [X.Y.Z] - YYYY-MM-DD` with today's date (and, as for `[0.1.0]`, a link for it at the bottom), and set `version` in `Cargo.toml` to `X.Y.Z`.
2. Merge the change to `main`. The release workflow tags the merge commit `vX.Y.Z` and releases it.

Pushing a `vX.Y.Z` tag by hand also starts a release, for example to release a commit other than the head of `main`:

```sh
git tag v0.1.1
git push origin v0.1.1
```

### What the release workflow does

The `release` workflow ([`.github/workflows/release.yml`](https://github.com/Trozz/mcp-server-core-rs/blob/main/.github/workflows/release.yml)) starts on a push to `main` that changes `Cargo.toml`, and on a pushed tag that matches `v*.*.*`. On Ubuntu with Rust 1.99.1, it:

| Step | What happens | Fails with |
|---|---|---|
| Version to release | The tag is `v` followed by `version` from `Cargo.toml`. On a push to `main`, when that tag already exists, the workflow stops here: `<tag> is already tagged: nothing to release`. On a pushed tag, the tag must match. | `tag <tag> does not match Cargo.toml version <version>` |
| Tests | `cargo test --all-features --locked`. | Any failing test |
| Release notes | Takes the section of `CHANGELOG.md` under `## [X.Y.Z]`, up to the next `## [` heading or the link definitions at the bottom. | `no CHANGELOG.md section for <tag>` when the section is missing or empty |
| GitHub release | `gh release create` titled with the tag, with those notes. On a push to `main` this also creates the tag on the merge commit. When a release for the tag already exists, for example on a re-run, it says so and goes on. | A `gh` error |
| crates.io | Gets a short-lived token through [trusted publishing](https://crates.io/docs/trusted-publishing) (`rust-lang/crates-io-auth-action`), then `cargo publish --locked`. | An auth error when the crate has no trusted publisher for this workflow |

The crates.io steps skip themselves when crates.io already has the version (`X.Y.Z is already on crates.io: skipping`). If the workflow fails after the GitHub release was created, re-run it: the release step and, once the version is on crates.io, the publish step both skip what is already done.

The package contains `src/`, `examples/`, the pages of this site, the README, changelog, security policy and both licences, as listed under `include` in `Cargo.toml`. CI runs `cargo package --locked` on every pull request and push to `main`, so a packaging problem shows up before a release is tagged.

### After publishing

[docs.rs](https://docs.rs/mcp-server-core) builds the API documentation for the new version by itself, with every feature on (`[package.metadata.docs.rs]` in `Cargo.toml`). Each version stays available at `https://docs.rs/mcp-server-core/<version>/`.

## This site

This site is built from `docs/` with [mdBook](https://rust-lang.github.io/mdBook/) and published to GitHub Pages at <https://trozz.github.io/mcp-server-core-rs/> by the `docs` workflow ([`.github/workflows/docs.yml`](https://github.com/Trozz/mcp-server-core-rs/blob/main/.github/workflows/docs.yml)):

- It runs on every push to `main`, and can be started by hand; it builds only from `main`.
- It installs the pinned tools with `scripts/install-docs-tools.sh`, builds with `scripts/build-docs.sh`, which also checks every internal link and anchor, and deploys `docs/book` to the `github-pages` environment.
- A run in progress is never cancelled: a newer push waits for it, and GitHub keeps only the newest waiting run, so the last push to `main` is the one published.

The site therefore describes `main`, which can be ahead of the latest release on crates.io. For the exact API of the version you depend on, use its docs.rs page. [Contributing](contributing.md#building-this-site) explains how to build the site locally.

## Repository setup (maintainers)

- **crates.io**: in the crate's settings on crates.io, add a trusted publisher for GitHub with owner `Trozz`, repository `mcp-server-core-rs` and workflow `release.yml`. No token secret is needed.
- **Workflow permissions**: every workflow defaults to `contents: read`. The release job requests `contents: write` to create the tag and GitHub release, `id-token: write` for trusted publishing, and the docs deploy job `pages: write` and `id-token: write`.
- **GitHub Pages**: under **Settings > Pages**, the source must be **GitHub Actions** for the docs workflow to publish.
