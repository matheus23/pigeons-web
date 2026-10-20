#!/usr/bin/env bash
# Builds the static site into dist/. The coop can serve it directly.
set -euo pipefail
cd "$(dirname "$0")"

variant="${1:-release}"
case "$variant" in
  release) cargo_profile=(--release); profile_dir=release ;;
  dev)     cargo_profile=();          profile_dir=debug ;;
  *)       echo "usage: $0 [release|dev]" >&2; exit 1 ;;
esac

cargo build --target wasm32-unknown-unknown -p pigeons-web "${cargo_profile[@]}"

rm -rf dist
mkdir -p dist
wasm-bindgen --target web --no-typescript \
  --out-dir dist/pkg \
  "target/wasm32-unknown-unknown/$profile_dir/pigeons_web.wasm"

if command -v wasm-opt >/dev/null && [ "$variant" = release ]; then
  wasm-opt -Oz --enable-bulk-memory --enable-nontrapping-float-to-int \
    dist/pkg/pigeons_web_bg.wasm -o dist/pkg/pigeons_web_bg.opt.wasm
  mv dist/pkg/pigeons_web_bg.opt.wasm dist/pkg/pigeons_web_bg.wasm
fi

cp web/index.html web/style.css dist/
printf 'built dist/ (%s)\n' "$(du -sh dist | cut -f1)"
