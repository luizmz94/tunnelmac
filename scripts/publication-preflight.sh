#!/bin/bash
# Shared gate: identical audit, complete-suite attestation and CI for both publishers.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -z $(git status --porcelain) ]] || { echo 'Publication requires a clean, committed tree.' >&2; exit 1; }
./scripts/audit-publication.py > /dev/null
command -v gitleaks >/dev/null || { echo 'Install gitleaks before publication (brew install gitleaks).' >&2; exit 1; }
if gitleaks git --help >/dev/null 2>&1; then
    gitleaks git --redact --no-banner "$PWD"
else
    gitleaks detect --source "$PWD" --redact --no-banner
fi
report="${TEST_REPORT:?Set TEST_REPORT to the full local suite output}"
grep -q '^OK: 0 falha(s)' "$report"
sha=$(git rev-parse HEAD)
[[ $(cat "$(dirname "$report")/TestCommit.txt") == "$sha" ]] || { echo 'Suite attestation does not match this commit.' >&2; exit 1; }
repo="${GITHUB_REPOSITORY:-luizmz94/tunnelmac}"
run=$(gh run list --repo "$repo" --commit "$sha" --workflow checks.yml --status success --json databaseId --jq '.[0].databaseId')
[[ -n "$run" ]] || { echo 'Successful checks.yml for this exact commit is required.' >&2; exit 1; }
