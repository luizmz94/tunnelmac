#!/bin/bash
# Updates Resources/Localizable.xcstrings with the texts the code uses, then lists what is
# still missing a translation. The source language is Portuguese (pt-BR): the texts in the
# code are the keys. Run after changing any user-facing text.
#
#   ./scripts/sync-strings.sh          # sync and report
#   ./scripts/sync-strings.sh --check  # fails when a text lacks a translation (CI)
set -euo pipefail
cd "$(dirname "$0")/.."
export CLANG_MODULE_CACHE_PATH="$PWD/.build/clang-cache"
export SWIFTPM_MODULECACHE_OVERRIDE="$PWD/.build/module-cache"

catalog=Resources/Localizable.xcstrings
languages=(en de es fr hi)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# A separate build folder compiles every file, so each one reports its texts.
for product in VPNGUI VPNHelper; do
    swift build --product "$product" --disable-sandbox --build-system native --scratch-path "$PWD/.build/strings" \
        --cache-path "$PWD/.build/cache" --manifest-cache local -Xswiftc -emit-localized-strings \
        -Xswiftc -emit-localized-strings-path -Xswiftc "$work" >/dev/null
done
arguments=()
for file in "$work"/*.stringsdata; do arguments+=(--stringsdata "$file"); done
xcrun xcstringstool sync "$catalog" "${arguments[@]}"

python3 - "$catalog" "${1:-}" "${languages[@]}" <<'PY'
import json, re, sys
path, mode, languages = sys.argv[1], sys.argv[2], sys.argv[3:]
catalog = json.load(open(path))
missing = {language: [] for language in languages}
for key, entry in catalog["strings"].items():
    if entry.get("extractionState") == "stale" or entry.get("shouldTranslate") is False:
        continue
    # Keys without words (format-only, symbols, IPs) need no translation.
    if not re.search(r"[A-Za-zÀ-ú]{2}", re.sub(r"%(\d\$)?(@|lld|ld|d|lf|f)", "", key)):
        entry["shouldTranslate"] = False
        continue
    for language in languages:
        if language not in entry.get("localizations", {}):
            missing[language].append(key)
json.dump(catalog, open(path, "w"), ensure_ascii=False, indent=2, sort_keys=True)
open(path, "a").write("\n")
total = sum(map(len, missing.values()))
for language, keys in missing.items():
    print(f"{language}: {len(keys)} sem tradução")
    for key in keys[:20]:
        print(f"    {key!r}")
if mode == "--check" and total:
    sys.exit("Textos sem tradução no catálogo.")
PY
