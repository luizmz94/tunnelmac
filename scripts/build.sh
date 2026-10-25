#!/bin/bash
# Builds TunnelMac.app with the LaunchDaemon helper into an isolated, versioned folder.
#
#   ./scripts/build.sh                      # local build, ad hoc signature (compiles/tests;
#                                           # the privileged service stays disabled)
#   SIGNING_IDENTITY="Developer ID Application: Name (TEAMID)" TEAM_ID=TEAMID ./scripts/build.sh
#   SIGNING_IDENTITY="Apple Development: Name (XXXXXXXXXX)" TEAM_ID=TEAMID ./scripts/build.sh
#
# Optional: OUTPUT_DIR (default build/<version>); SIGNING_KEYCHAIN, a keychain outside the
# search list that holds the identity (CI). Nothing secret is read or stored here.
set -euo pipefail
cd "$(dirname "$0")/.."
export CLANG_MODULE_CACHE_PATH="$PWD/.build/clang-cache"
export SWIFTPM_MODULECACHE_OVERRIDE="$PWD/.build/module-cache"

constants=Sources/VPNHelperShared/Constants.swift
version=$(sed -n 's/.*static let version = "\(.*\)".*/\1/p' "$constants")
build=$(sed -n 's/.*static let build = "\(.*\)".*/\1/p' "$constants")
[[ -n "$version" && -n "$build" ]] || { echo "Versão não encontrada em $constants" >&2; exit 1; }
identity="${SIGNING_IDENTITY:--}"
team="${TEAM_ID:-}"
out="${OUTPUT_DIR:-$PWD/build/$version}"
app="$out/TunnelMac.app"

# Never overwrite a bundle that is running (personal instance with tunnels).
if pgrep -f "$app/Contents/MacOS/VPNGUI" >/dev/null 2>&1; then
    echo "O app em $app está em execução; feche-o ou use OUTPUT_DIR para outra pasta." >&2
    exit 1
fi

arch="${ARCH:-$(uname -m)}"
[[ "$arch" == arm64 || "$arch" == x86_64 ]] || { echo "Unsupported ARCH: $arch" >&2; exit 1; }
for product in VPNGUI VPNHelper VPNSupervisor; do
    swift build --product "$product" --arch "$arch" --disable-sandbox --build-system native --cache-path "$PWD/.build/cache" --manifest-cache local -c release
done

bin_dir=$(swift build --arch "$arch" --disable-sandbox --build-system native --cache-path "$PWD/.build/cache" --manifest-cache local -c release --show-bin-path)
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Library/LaunchDaemons" "$app/Contents/Resources"
cp Resources/AppIcon.icns "$app/Contents/Resources/AppIcon.icns"
cp Resources/Brand/*.png "$app/Contents/Resources/"
cp "$bin_dir"/VPNGUI "$app/Contents/MacOS/VPNGUI"
cp "$bin_dir"/VPNHelper "$app/Contents/MacOS/VPNHelper"
cp "$bin_dir"/VPNSupervisor "$app/Contents/MacOS/VPNSupervisor"
cp Resources/com.luiz.vpngui.helper.plist "$app/Contents/Library/LaunchDaemons/com.luiz.vpngui.helper.plist"
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>VPNGUI</string>
<key>CFBundleIdentifier</key><string>com.luiz.vpngui</string>
<key>CFBundleName</key><string>TunnelMac</string>
<key>CFBundleDisplayName</key><string>TunnelMac</string>
<key>CFBundleIconFile</key><string>AppIcon.icns</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$version</string>
<key>CFBundleVersion</key><string>$build</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
<key>NSHighResolutionCapable</key><true/>
<key>NSPrincipalClass</key><string>NSApplication</string>
</dict></plist>
PLIST
plutil -lint "$app/Contents/Info.plist" "$app/Contents/Library/LaunchDaemons/com.luiz.vpngui.helper.plist" >/dev/null

# Each component is signed individually, innermost first (no --deep).
if [[ "$identity" == "-" ]]; then
    options=(--force --sign -)
    echo "Assinatura ad hoc: compila e testa; o serviço privilegiado fica desabilitado (sem Team ID)."
else
    # The identity can be a SHA-1 hash, so its argument text cannot tell us the
    # certificate type. Timestamp certificate-backed builds consistently.
    options=(--force --sign "$identity" --options runtime --timestamp)
    [[ -z "${SIGNING_KEYCHAIN:-}" ]] || options+=(--keychain "$SIGNING_KEYCHAIN")
fi
codesign "${options[@]}" --identifier com.luiz.vpngui.supervisor "$app/Contents/MacOS/VPNSupervisor"
codesign "${options[@]}" --identifier com.luiz.vpngui.helper "$app/Contents/MacOS/VPNHelper"
codesign "${options[@]}" --identifier com.luiz.vpngui "$app"
codesign --verify --strict --deep "$app"

if [[ "$identity" != "-" ]]; then
    for component in "$app/Contents/MacOS/VPNSupervisor" "$app/Contents/MacOS/VPNHelper" "$app"; do
        signed_team=$(codesign -dv "$component" 2>&1 | sed -n 's/^TeamIdentifier=//p')
        if [[ -z "$signed_team" || "$signed_team" == "not set" ]]; then echo "Sem Team ID em $component" >&2; exit 1; fi
        if [[ -n "$team" && "$signed_team" != "$team" ]]; then echo "Team $signed_team difere de TEAM_ID=$team em $component" >&2; exit 1; fi
        team="$signed_team"
        flags=$(codesign -dv "$component" 2>&1 | sed -n 's/.*flags=\(0x[0-9a-f]*\)(\(.*\)).*/\2/p')
        [[ "$flags" == *runtime* ]] || { echo "Hardened runtime ausente em $component" >&2; exit 1; }
    done
    # The same requirements the app and helper enforce over XPC.
    codesign --verify -R="identifier \"com.luiz.vpngui\" and anchor apple generic and certificate leaf[subject.OU] = \"$team\"" "$app"
    codesign --verify -R="identifier \"com.luiz.vpngui.helper\" and anchor apple generic and certificate leaf[subject.OU] = \"$team\"" "$app/Contents/MacOS/VPNHelper"
    codesign --verify -R="identifier \"com.luiz.vpngui.supervisor\" and anchor apple generic and certificate leaf[subject.OU] = \"$team\"" "$app/Contents/MacOS/VPNSupervisor"
    echo "Assinado para o Team $team; requisitos XPC conferidos."
fi
printf 'App compilado: %s (versão %s, build %s)\n' "$app" "$version" "$build"
