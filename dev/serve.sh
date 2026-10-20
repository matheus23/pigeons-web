#!/usr/bin/env bash
# Serves dist/ for development. Any static file server works; the page is
# self-contained (it is its own iroh endpoint, so there is no backend).
#
#   ./build.sh && dev/serve.sh [port]
set -euo pipefail
cd "$(dirname "$0")/.."
port="${1:-8787}"
exec node dev/serve.mjs dist "$port"
