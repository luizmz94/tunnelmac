#!/bin/bash
# Draft only. Publishing is a separate final action after review and validation.
set -euo pipefail
cd "$(dirname "$0")/.."
repo=luizmz94/tunnelmac
[[ $(git remote get-url origin) == "https://github.com/$repo.git" ]] || { echo 'Repository rename/origin update is pending.' >&2; exit 1; }
[[ -z $(git status --porcelain) ]] || { echo 'Commit and validate the complete working tree first.' >&2; exit 1; }
./scripts/publication-preflight.sh
visibility=$(gh repo view "$repo" --json visibility --jq .visibility)
[[ "$visibility" == PUBLIC ]] || { echo 'Publicity audit/visibility change is pending.' >&2; exit 1; }
default=$(gh repo view "$repo" --json defaultBranchRef --jq .defaultBranchRef.name)
[[ $(git branch --show-current) == "$default" ]]
[[ $(git rev-parse HEAD) == $(git ls-remote origin "refs/heads/$default" | cut -f1) ]]
version=$(sed -n 's/.*static let releaseVersion = "\(.*\)".*/\1/p' Sources/VPNHelperShared/Constants.swift)
# One stapled TunnelMac.app per architecture (both arm64 and x86_64).
(( $# > 0 )) || { echo 'Pass the signed and stapled TunnelMac.app of each architecture' >&2; exit 1; }
report="${TEST_REPORT:?Set TEST_REPORT to the full graphical suite output for the validated commit}"
grep -q '^OK: 0 falha(s)' "$report"
sha=$(git rev-parse HEAD)
if gh release view "v$version" --repo "$repo" >/dev/null 2>&1; then echo 'Release exists; refusing replacement.' >&2; exit 1; fi
if git ls-remote --exit-code --tags origin "refs/tags/v$version" >/dev/null 2>&1; then echo 'Tag exists; refusing reuse.' >&2; exit 1; fi
out="$PWD/build/releases/$version"
for app in "$@"; do ./scripts/package-release.sh "$app"; done
notes=packaging/release-notes.md
python3 -I scripts/appcast.py "$version" --dir "$out" --notes "$notes" \
  --tools "${SPARKLE_TOOLS_DIR:-$PWD/.build/artifacts/sparkle/Sparkle/bin}"
prerelease=()
[[ "$version" != *-* ]] || prerelease=(--prerelease)
gh release create "v$version" --repo "$repo" --target "$sha" --draft ${prerelease[@]+"${prerelease[@]}"} \
  --title "TunnelMac $version" --notes-file "$notes" \
  "$out"/TunnelMac-"$version"-*.zip "$out/SHA256SUMS" "$out/appcast-arm64.xml" "$out/appcast-x86_64.xml"
echo 'Draft uploaded. Verify artifacts and lifecycle checks before publishing the draft.'
