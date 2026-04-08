#!/usr/bin/env bash
set -euo pipefail

# Check recent rust-l1-nightly-health workflow runs and verify green streak.
# Usage:
#   ./scripts/check_nightly_green_streak.sh [owner] [repo] [required_streak]

OWNER="${1:-ProfAlexQI}"
REPO="${2:-TrillionniumChain}"
REQUIRED="${3:-3}"
WORKFLOW_FILE="rust-l1-nightly-health.yml"

URL="https://api.github.com/repos/${OWNER}/${REPO}/actions/workflows/${WORKFLOW_FILE}/runs?per_page=20&status=completed"

fetch_with_curl() {
  curl -fsSL "$URL"
}

fetch_with_gh() {
  if ! command -v gh >/dev/null 2>&1; then
    return 1
  fi
  gh run list -R "${OWNER}/${REPO}" --workflow "$WORKFLOW_FILE" --limit 20 --json conclusion,status \
    | jq -c '{workflow_runs: [.[] | select(.status=="completed") | {conclusion: .conclusion}]}'
}

if JSON="$(fetch_with_curl 2>/dev/null)"; then
  :
elif JSON="$(fetch_with_gh 2>/dev/null)"; then
  :
else
  echo "failed to fetch workflow runs via GitHub API and gh fallback" >&2
  exit 14
fi

conclusion_lines="$(echo "$JSON" | jq -r '.workflow_runs[] | .conclusion' | head -n 20)"

if [ -z "$conclusion_lines" ]; then
  echo "no completed workflow runs found for $WORKFLOW_FILE" >&2
  exit 12
fi

streak=0
seen=0
while IFS= read -r c; do
  [ -z "$c" ] && continue
  seen=$((seen+1))
  if [ "$c" = "success" ]; then
    streak=$((streak+1))
  else
    break
  fi
done <<< "$conclusion_lines"

echo "nightly.workflow=$WORKFLOW_FILE"
echo "nightly.runs_checked=$seen"
echo "nightly.green_streak=$streak"
echo "nightly.required_streak=$REQUIRED"

if [ "$streak" -lt "$REQUIRED" ]; then
  echo "nightly green streak insufficient: $streak < $REQUIRED" >&2
  exit 13
fi

echo "nightly green streak check: PASS"