#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Normalize locale/time-sensitive output so release guidance is deterministic
# across local shells and CI runners.
export TZ=UTC
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

cd "$ROOT_DIR"

VERSION="$(node -p "require('./package.json').version")"
CHANGELOG_FILE="$ROOT_DIR/CHANGELOG.md"

if [[ ! -f "$CHANGELOG_FILE" ]]; then
  echo "[release-ready] FAIL: CHANGELOG.md not found at $CHANGELOG_FILE"
  exit 1
fi

if ! grep -Eq "^## \[$VERSION\]( |$)" "$CHANGELOG_FILE"; then
  echo "[release-ready] FAIL: CHANGELOG.md missing version section: ## [$VERSION]"
  echo "[release-ready] hint: add section like '## [$VERSION] - $(date '+%Y-%m-%d')'"
  exit 1
fi

echo "[release-ready] version/changelog check passed for $VERSION"
bash "$ROOT_DIR/scripts/release-preflight.sh"

echo "[release-ready] PASS"
