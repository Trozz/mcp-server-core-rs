#!/usr/bin/env bash
# Installs the pinned documentation tools for Linux x86_64 (CI) into the directory given as $1.
set -euo pipefail

dest="${1:?usage: install-docs-tools.sh <bin-dir>}"
mkdir -p "$dest"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

MDBOOK_VERSION=0.5.4
MDBOOK_SHA256=5222beabd3e37dc5be0d18ff99b79058469354db5c220153a1b92db5ba12be89
MERMAID_VERSION=0.17.1
MERMAID_SHA256=42aca57eea8521971cc595fe4bb853c5b8b7d9f7138a2ec9f14a0a72c210922d
LYCHEE_VERSION=0.24.2
LYCHEE_SHA256=73657a111819a30c47c08352896796f23d64e4eb2b3ed39b6d32149241566fc5

fetch() {
  local url="$1" sha="$2" file
  file="$tmp/$(basename "$url")"
  curl -fsSL -o "$file" "$url"
  echo "$sha  $file" | sha256sum -c - >/dev/null
  tar -xzf "$file" -C "$tmp"
}

fetch "https://github.com/rust-lang/mdBook/releases/download/v${MDBOOK_VERSION}/mdbook-v${MDBOOK_VERSION}-x86_64-unknown-linux-musl.tar.gz" "$MDBOOK_SHA256"
fetch "https://github.com/badboy/mdbook-mermaid/releases/download/v${MERMAID_VERSION}/mdbook-mermaid-v${MERMAID_VERSION}-x86_64-unknown-linux-musl.tar.gz" "$MERMAID_SHA256"
fetch "https://github.com/lycheeverse/lychee/releases/download/lychee-v${LYCHEE_VERSION}/lychee-x86_64-unknown-linux-musl.tar.gz" "$LYCHEE_SHA256"

install -m 0755 "$tmp/mdbook" "$tmp/mdbook-mermaid" "$tmp/lychee-x86_64-unknown-linux-musl/lychee" "$dest/"
"$dest/mdbook" --version
"$dest/mdbook-mermaid" --version
"$dest/lychee" --version
