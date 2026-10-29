#!/bin/bash
# Disk image of a signed, notarized and stapled TunnelMac.app: the app, an Applications
# link and the branded window (packaging/dmg). The image is signed, notarized and stapled
# too. Run after package-release.sh; the zip stays the format of Sparkle and Homebrew.
#
#   SIGNING_IDENTITY=… NOTARY_PROFILE=… ./scripts/make-dmg.sh TunnelMac.app
#   ./scripts/make-dmg.sh --layout TunnelMac.app   # maintainers: rewrite packaging/dmg/DS_Store with Finder
#
# The art: swift packaging/dmg/render-background.swift (window background) and
# swift packaging/dmg/render-install-gif.swift <dir> (frames of docs/assets/install.gif).
# Without SIGNING_IDENTITY (local preview) the image is left unsigned and not notarized.
# SIGNING_KEYCHAIN and NOTARY_KEYCHAIN select other keychains (CI).
set -euo pipefail
cd "$(dirname "$0")/.."
layout=false
[[ "${1:-}" != --layout ]] || { layout=true; shift; }
release=$(sed -n 's/.*static let releaseVersion = "\(.*\)".*/\1/p' Sources/VPNHelperShared/Constants.swift)
app="${1:?Pass TunnelMac.app}"
[[ $(basename "$app") == TunnelMac.app && -d "$app" ]] || { echo "App não encontrado: $app" >&2; exit 1; }
arch=$(lipo -archs "$app/Contents/MacOS/VPNGUI")
[[ "$arch" == arm64 || "$arch" == x86_64 ]] || { echo "Arquitetura não suportada: $arch" >&2; exit 1; }
design=packaging/dmg
volume=TunnelMac # The layout's background alias resolves by this name: keep it fixed.
out="${RELEASE_DIR:-$PWD/build/releases/$release}"
dmg="$out/TunnelMac-$release-$arch.dmg"
$layout || [[ ! -e "$dmg" ]] || { echo 'Disk image already exists; refusing overwrite.' >&2; exit 1; }
[[ ! -d "/Volumes/$volume" ]] || { echo "Ejete /Volumes/$volume antes." >&2; exit 1; }

work=$(mktemp -d)
mounted=''
cleanup() { [[ -z "$mounted" ]] || hdiutil detach -quiet -force "$mounted" || true; rm -rf "$work"; }
trap cleanup EXIT
stage="$work/stage"
mkdir -p "$stage/.background"
ditto "$app" "$stage/TunnelMac.app"
SetFile -a E "$stage/TunnelMac.app" # label "TunnelMac", without .app
ln -s /Applications "$stage/Applications"
tiffutil -cathidpicheck "$design/background.png" "$design/background@2x.png" -out "$stage/.background/background.tiff" 2>/dev/null
cp "$app/Contents/Resources/AppIcon.icns" "$stage/.VolumeIcon.icns"
$layout || cp "$design/DS_Store" "$stage/.DS_Store"

hdiutil create -quiet -volname "$volume" -srcfolder "$stage" -fs HFS+ -format UDRW -ov "$work/rw.dmg"
mounted=$(hdiutil attach -nobrowse -noautoopen -readwrite "$work/rw.dmg" | sed -n 's|.*\(/Volumes/.*\)$|\1|p' | head -1)
[[ "$mounted" == "/Volumes/$volume" ]] || { echo "Montado em $mounted, esperado /Volumes/$volume" >&2; exit 1; }
SetFile -a C "$mounted" # use .VolumeIcon.icns

if $layout; then
    # Icon positions and window size must match packaging/dmg/render-background.swift.
    osascript <<APPLESCRIPT
tell application "Finder"
    tell disk "$volume"
        open
        set current view of container window to icon view
        set toolbar visible of container window to false
        set statusbar visible of container window to false
        set bounds of container window to {200, 120, 860, 568}
        set options to the icon view options of container window
        set arrangement of options to not arranged
        set icon size of options to 112
        set text size of options to 14
        set background picture of options to file ".background:background.tiff"
        set position of item "TunnelMac.app" of container window to {180, 210}
        set position of item "Applications" of container window to {480, 210}
        update without registering applications
        delay 2
        close
    end tell
end tell
APPLESCRIPT
    sleep 2
    cp "$mounted/.DS_Store" "$design/DS_Store"
    echo "Layout salvo em $design/DS_Store"
fi
chmod -Rf go-w "$mounted" || true
hdiutil detach -quiet "$mounted"; mounted=''
$layout && exit 0

mkdir -p "$out"
hdiutil convert -quiet "$work/rw.dmg" -format ULFO -o "$dmg"
if [[ -n "${SIGNING_IDENTITY:-}" ]]; then
    keychain=()
    [[ -z "${SIGNING_KEYCHAIN:-}" ]] || keychain=(--keychain "$SIGNING_KEYCHAIN")
    codesign --sign "$SIGNING_IDENTITY" --timestamp ${keychain[@]+"${keychain[@]}"} "$dmg"
    notary=()
    [[ -z "${NOTARY_KEYCHAIN:-}" ]] || notary=(--keychain "$NOTARY_KEYCHAIN")
    xcrun notarytool submit "$dmg" --keychain-profile "${NOTARY_PROFILE:?Defina NOTARY_PROFILE}" ${notary[@]+"${notary[@]}"} --wait
    xcrun stapler staple "$dmg"
    xcrun stapler validate "$dmg"
    spctl --assess --type open --context context:primary-signature --verbose=2 "$dmg"
else
    echo 'Sem SIGNING_IDENTITY: imagem de prévia, sem assinatura nem notarização.' >&2
fi
# SHA256SUMS lists every archive and disk image of this release.
(cd "$out" && shopt -s nullglob && shasum -a 256 TunnelMac-"$release"-*.zip TunnelMac-"$release"-*.dmg > SHA256SUMS)
echo "$dmg"
