#!/bin/bash
# Focused regressions: no WindowServer, real VPN, Keychain or privileged registration.
set -euo pipefail
cd "$(dirname "$0")/.."
export CLANG_MODULE_CACHE_PATH="$PWD/.build/clang-cache"
export SWIFTPM_MODULECACHE_OVERRIDE="$PWD/.build/module-cache"
swift test --disable-sandbox --build-system native --cache-path "$PWD/.build/cache" --manifest-cache local "$@"
