#!/bin/bash
# README demo: the real interface over fictitious connections, built from the local checks
# runner (never part of the distributed app). No VPN, privileges, network or service.
#
#   ./scripts/showcase.sh             # opens the demo; Conectar/Desconectar replay client output
#   ./scripts/showcase.sh --capture   # scripted tour; writes the images to docs/assets
#
# Optional: OUTPUT_DIR (default build/showcase).
set -euo pipefail
cd "$(dirname "$0")/.."
export CLANG_MODULE_CACHE_PATH="$PWD/.build/clang-cache"
export SWIFTPM_MODULECACHE_OVERRIDE="$PWD/.build/module-cache"
version=$(sed -n 's/.*static let version = "\(.*\)".*/\1/p' Sources/VPNHelperShared/Constants.swift)
build=$(sed -n 's/.*static let build = "\(.*\)".*/\1/p' Sources/VPNHelperShared/Constants.swift)
out="${OUTPUT_DIR:-$PWD/build/showcase}"
app="$out/TunnelMac.app"
identifier=com.luiz.vpngui.local-checks.showcase

if pgrep -f "$app/Contents/MacOS/VPNGUI" >/dev/null 2>&1; then
    echo "A demonstração já está aberta; feche-a antes." >&2; exit 1
fi
swift build --package-path IntegrationRunner --scratch-path "$PWD/.build/integration" --product VPNIntegrationRunner --disable-sandbox --build-system native --cache-path "$PWD/.build/cache" --manifest-cache local -c debug
bin_dir=$(swift build --package-path IntegrationRunner --scratch-path "$PWD/.build/integration" --disable-sandbox --build-system native --cache-path "$PWD/.build/cache" --manifest-cache local -c debug --show-bin-path)
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$bin_dir/VPNIntegrationRunner" "$app/Contents/MacOS/VPNGUI"
# The app links Sparkle (never started here: the showcase is a local-checks bundle).
mkdir -p "$app/Contents/Frameworks"
ditto "$bin_dir/Sparkle.framework" "$app/Contents/Frameworks/Sparkle.framework"
install_name_tool -add_rpath @executable_path/../Frameworks "$app/Contents/MacOS/VPNGUI"
cp Resources/AppIcon.icns "$app/Contents/Resources/AppIcon.icns"
cp Resources/Brand/*.png "$app/Contents/Resources/"
scripts/compile-strings.sh "$app"
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleDevelopmentRegion</key><string>en</string>
<key>CFBundleLocalizations</key><array>$(scripts/compile-strings.sh --plist)</array>
<key>CFBundleExecutable</key><string>VPNGUI</string>
<key>CFBundleIdentifier</key><string>$identifier</string>
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
codesign --force --sign - --identifier "$identifier" "$app"

if [[ "${1:-}" != "--capture" ]]; then
    open -n "$app" --args --showcase
    exit 0
fi

captures="$out/captures"
rm -rf "$captures"
open -W -n --stdout "$out/showcase.log" --stderr "$out/showcase.log" "$app" --args --showcase-capture "$captures" -AppleLanguages "(en)" # The README is in English.
assets=docs/assets
mkdir -p "$assets"
for image in "$captures"/*.png; do cp "$image" "$assets/"; done
if command -v ffmpeg >/dev/null; then
    ffmpeg -loglevel error -y -framerate 12 -i "$captures/frames-connect/%04d.png" \
        -vf "fps=10,scale=860:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=128:stats_mode=diff[p];[b][p]paletteuse=dither=sierra2_4a:diff_mode=rectangle" \
        "$assets/connect.gif"
else
    echo "ffmpeg não encontrado (brew install ffmpeg); o GIF não foi gerado." >&2
fi
ls -lh "$assets"
