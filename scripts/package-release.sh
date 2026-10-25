#!/bin/bash
# Package only an already signed, notarized, stapled artifact. No credentials in CI.
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(sed -n 's/.*static let version = "\(.*\)".*/\1/p' Sources/VPNHelperShared/Constants.swift)
release=$(sed -n 's/.*static let releaseVersion = "\(.*\)".*/\1/p' Sources/VPNHelperShared/Constants.swift)
app="${1:-$PWD/build/$version/TunnelMac.app}"
[[ $(basename "$app") == TunnelMac.app ]] || exit 1
./scripts/verify-bundle.sh "$app"
team=''
arch=''
for component in "$app" "$app/Contents/MacOS/VPNHelper" "$app/Contents/MacOS/VPNSupervisor"; do
    details=$(codesign -dvv "$component" 2>&1)
    grep -q 'Authority=Developer ID Application' <<<"$details"
    grep -q 'Timestamp=' <<<"$details"
    grep -q 'flags=.*runtime' <<<"$details"
    current_team=$(sed -n 's/^TeamIdentifier=//p' <<<"$details")
    [[ -n "$current_team" && ( -z "$team" || "$team" == "$current_team" ) ]] || exit 1
    team="$current_team"
    executable="$component"
    [[ ! -d "$component" ]] || executable="$component/Contents/MacOS/VPNGUI"
    current_arch=$(lipo -archs "$executable")
    [[ -z "$arch" || "$arch" == "$current_arch" ]] || { echo 'Architecture mismatch' >&2; exit 1; }
    arch="$current_arch"
done
# One archive per architecture. The x86_64 build is cross-compiled; checks.yml runs the
# full suite on an Intel runner for the same commit before a release is made.
[[ "$arch" == arm64 || "$arch" == x86_64 ]] || { echo "Unsupported release architecture: $arch" >&2; exit 1; }
xcrun stapler validate "$app"
spctl --assess --type execute --verbose=2 "$app"
[[ $(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$app/Contents/Info.plist") == "$version" ]]
out="${RELEASE_DIR:-$PWD/build/releases/$release}"
mkdir -p "$out"
zip="$out/TunnelMac-$release-$arch.zip"
[[ ! -e "$zip" ]] || { echo 'Release archive already exists; refusing overwrite.' >&2; exit 1; }
ditto -c -k --keepParent "$app" "$zip"
# SHA256SUMS lists every archive of this release (both architectures once both are packaged).
(cd "$out" && shasum -a 256 TunnelMac-"$release"-*.zip > SHA256SUMS)
echo "$zip"
