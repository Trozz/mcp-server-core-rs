# Contributing

Thank you for helping. Bug reports, questions and pull requests are all welcome.

## Reporting

- **Security problems**: please do not open an issue. See [SECURITY.md](SECURITY.md).
- **Bugs**: open an issue with what you did, what you expected and what happened, the crate and
  Rust versions, and logs with secrets removed.
- **Ideas**: open an issue before a large change, so we can agree on the shape first.

## Developing

The toolchain is pinned in `rust-toolchain.toml`; `rustup` installs it on first use.

```sh
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy --all-targets --no-default-features -- -D warnings
cargo test --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
```

CI runs these, plus `cargo deny check`, a build on the minimum supported Rust version (see
`rust-version` in `Cargo.toml`) and `cargo package`.

To try a change against a real client, run an example:

```sh
PUBLIC_URL=http://localhost:8443 INSECURE_HTTP=true \
OAUTH_SIGNING_KEY=$(openssl rand -hex 32) OAUTH_ADMIN_PASSWORD='a long password' \
LOG_FORMAT=pretty cargo run --example notes
```

## Guidelines

- Keep the public API small and documented: every public item needs a doc comment
  (`missing_docs` is on), and examples in docs and the README are compiled as tests.
- Security-relevant behaviour (sign-in, tokens, limits, logging) needs a test that would fail
  without the change.
- Never log secrets, credentials, session ids or content. Content may be logged only when
  `observability::content_logging_enabled()` is true.
- No `unsafe` code.
- Update `CHANGELOG.md` under the unreleased version.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/), such as
  `fix: count wrong static tokens towards the sign-in limit`.

## Releasing

1. Move the changelog entries under the new version with today's date and set `version` in
   `Cargo.toml`.
2. Merge to `main`, then tag the merge commit `vX.Y.Z` and push the tag.
3. The release workflow checks the tag matches `Cargo.toml`, runs the tests, creates the GitHub
   release and, when the `CARGO_REGISTRY_TOKEN` secret is set, publishes to crates.io.

## Licence

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this crate by you, as defined in the Apache-2.0 licence, shall be dual licensed under the MIT and
Apache-2.0 licences, without any additional terms or conditions.
