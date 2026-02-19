#!/usr/bin/env bash
set -euo pipefail

# Check recent rust-l1-nightly-health workflow runs and verify green streak.
# Usage:
#   ./scripts/check_nightly_green_streak.sh [owner] [repo] [required_streak]

OWNER="${1:-ProfAlexQI}"
REPO="${2:-TrillionniumChain}"
REQUIRED="${3:-3}"
WORKFLOW_NAME="rust-l1-nightly-health"

URL="https://api.github.com/repos/${OWNER}/${REPO}/actions/runs?per_page=20"

fetch_with_curl() {
  curl -fsSL "$URL"
}

fetch_with_gh() {
  gh run list -R "${OWNER}/${REPO}" --workflow "$WORKFLOW_NAME" --limit 20 --json conclusion 2>/dev/null | jq -c '{workflow_runs: [.[] | {conclusion: .conclusion}]}'
}

if JSON="$(fetch_with_curl 2>/dev/null)"; then
  :
elif command -v gh >/dev/null 2>&1; then
  JSON="$(fetch_with_gh)"
else
  echo "failed to fetch workflow runs via GitHub API, and gh is unavailable" >&2
  exit 14
fi

conclusion_lines="$(echo "$JSON" | jq -r --arg wf "$WORKFLOW_NAME" '.workflow_runs[] | .conclusion' | head -n 20)"

if [ -z "$conclusion_lines" ]; then
  echo "no workflow runs found for $WORKFLOW_NAME" >&2
  exit 12
fi

streak=0
while IFS= read -r c; do
  [ -z "$c" ] && continue
  if [ "$c" = "success" ]; then
    streak=$((streak+1))
  else
    break
  fi
done <<< "$conclusion_lines"

echo "nightly.green_streak=$streak"
echo "nightly.required_streak=$REQUIRED"

if [ "$streak" -lt "$REQUIRED" ]; then
  echo "nightly green streak insufficient: $streak < $REQUIRED" >&2
  exit 13
fi

echo "nightly green streak check: PASS"
