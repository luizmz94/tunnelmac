#!/bin/bash
# Compiles Resources/Localizable.xcstrings into <app>/Contents/Resources/<language>.lproj.
# The texts in the code are Portuguese (pt-BR) and are the catalog's keys. English is the
# development region: the fallback for system languages the app does not have.
#
#   ./scripts/compile-strings.sh path/to/TunnelMac.app
#   ./scripts/compile-strings.sh --plist    # the CFBundleLocalizations entries
set -euo pipefail
cd "$(dirname "$0")/.."
languages=(en de es fr hi pt-BR)

if [[ "${1:-}" == "--plist" ]]; then
    printf '<string>%s</string>' "${languages[@]}"
    exit 0
fi
resources="$1/Contents/Resources"
mkdir -p "$resources"
xcrun xcstringstool compile Resources/Localizable.xcstrings --output-directory "$resources"
# Every language needs its folder, even one whose texts are all the keys (pt-BR).
for language in "${languages[@]}"; do
    mkdir -p "$resources/$language.lproj"
    [[ -e "$resources/$language.lproj/Localizable.strings" ]] ||
        printf '/* The keys are the Portuguese source texts. */\n' > "$resources/$language.lproj/Localizable.strings"
done
