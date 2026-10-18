#!/usr/bin/env bash
# Builds the documentation site into docs/book and checks every internal link and anchor.
# Needs mdbook, mdbook-mermaid and lychee on PATH (scripts/install-docs-tools.sh installs them).
set -euo pipefail
cd "$(dirname "$0")/.."

if ! mdbook-mermaid install docs >/dev/null 2>&1; then
  echo "mdbook-mermaid install docs failed" >&2
  exit 1
fi
mdbook build docs
# 404.html uses root-relative links to the published site path, which only resolve on Pages.
lychee --offline --include-fragments --no-progress --exclude-path docs/book/404.html 'docs/book/**/*.html'
