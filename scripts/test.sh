#!/bin/bash
# Local checks in an isolated runner bundle. No VPN, privileges, network or service registration.
set -euo pipefail
cd "$(dirname "$0")/.."
export CLANG_MODULE_CACHE_PATH="$PWD/.build/clang-cache"
export SWIFTPM_MODULECACHE_OVERRIDE="$PWD/.build/module-cache"
version=$(sed -n 's/.*static let version = "\(.*\)".*/\1/p' Sources/VPNHelperShared/Constants.swift)
out="${OUTPUT_DIR:-$PWD/build/$version}"
mkdir -p "$out"
./scripts/test-regressions.sh 2>&1 | tee "$out/RegressionResults.txt"
SIGNING_IDENTITY=- TEAM_ID= OUTPUT_DIR="$out" ./scripts/build.sh
# Launch the test executable as a normal macOS app, so Keychain, loopback and XPC use the
# same environment as the actual app, rather than a restricted shell. Always ad hoc.
runner="$out/VPNGUILocalChecks-$version.app"
runner_identifier="com.luiz.vpngui.local-checks.v${version//./-}"
if pgrep -f "$runner/Contents/MacOS/VPNGUI" >/dev/null 2>&1; then
    echo "Test runner is already running; use a different OUTPUT_DIR." >&2; exit 1
fi
rm -rf "$runner"
mkdir -p "$runner/Contents/MacOS"
swift build --package-path IntegrationRunner --scratch-path "$PWD/.build/integration" --product VPNIntegrationRunner --disable-sandbox --build-system native --cache-path "$PWD/.build/cache" --manifest-cache local -c debug
bin_dir=$(swift build --package-path IntegrationRunner --scratch-path "$PWD/.build/integration" --disable-sandbox --build-system native --cache-path "$PWD/.build/cache" --manifest-cache local -c debug --show-bin-path)
cp "$bin_dir/VPNIntegrationRunner" "$runner/Contents/MacOS/VPNGUI"
# The app links Sparkle; same framework and rpath as the bundle built above.
ditto "$out/TunnelMac.app/Contents/Frameworks" "$runner/Contents/Frameworks"
install_name_tool -add_rpath @executable_path/../Frameworks "$runner/Contents/MacOS/VPNGUI"
cp "$out/TunnelMac.app/Contents/MacOS/VPNSupervisor" "$runner/Contents/MacOS/VPNSupervisor"
cp "$out/TunnelMac.app/Contents/Info.plist" "$runner/Contents/Info.plist"
cp -R "$out/TunnelMac.app/Contents/Resources" "$runner/Contents/Resources"
# The daemon plist (never registered: other identifier, no helper binary) lets the
# Homebrew sandbox check exercise the same restricted-mode detection as the app.
cp -R "$out/TunnelMac.app/Contents/Library" "$runner/Contents/Library"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $runner_identifier" "$runner/Contents/Info.plist"
/usr/libexec/PlistBuddy -c 'Set :CFBundleName TunnelMac Local Checks' "$runner/Contents/Info.plist"
/usr/libexec/PlistBuddy -c 'Set :CFBundleDisplayName TunnelMac Local Checks' "$runner/Contents/Info.plist"
codesign --force --sign - --identifier com.luiz.vpngui.supervisor "$runner/Contents/MacOS/VPNSupervisor"
codesign --force --sign - --identifier "$runner_identifier" "$runner"
if [[ "${1:-}" == "--prepare-only" ]]; then
    printf 'Test runner preparado: %s\n' "$runner"
    exit 0
fi
rm -f "$out/TestResults.txt" "$out/TestResults.txt.stderr" "$out/TestCommit.txt"
# The checks compare messages in the source language (pt-BR), whatever the Mac uses.
open -W -n "$runner" --args --headless -AppleLanguages "(pt-BR)"
cat "$out/TestResults.txt"
if ! /usr/bin/grep -q '^OK: 0 falha(s)' "$out/TestResults.txt"; then exit 1; fi

# Attestation used by draft publication; dirty development runs still run normally.
rm -f "$out/TestCommit.txt"
if [[ -z $(git status --porcelain) ]]; then git rev-parse HEAD > "$out/TestCommit.txt"; fi
