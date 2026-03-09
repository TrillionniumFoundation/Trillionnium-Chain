#!/usr/bin/env bash
set -euo pipefail

README_PATH="${1:-README.md}"

if [[ ! -f "$README_PATH" ]]; then
  echo "[readme-link-check][FAIL] README not found: $README_PATH" >&2
  exit 2
fi

missing=0
checked=0

while IFS= read -r link; do
  target="${link#*(}"
  target="${target%)*}"

  # Ignore anchors and external links.
  case "$target" in
    \#*|http://*|https://*|mailto:*)
      continue
      ;;
  esac

  # Remove optional query/anchor suffix.
  target="${target%%\#*}"
  target="${target%%\?*}"

  [[ -n "$target" ]] || continue

  checked=$((checked + 1))
  if [[ ! -e "$target" ]]; then
    echo "[readme-link-check][MISSING] $target"
    missing=$((missing + 1))
  fi
done < <(grep -Eo '\[[^][]+\]\([^)]+\)' "$README_PATH" || true)

echo "[readme-link-check] checked=$checked missing=$missing"

if [[ "$missing" -ne 0 ]]; then
  exit 1
fi

echo "[readme-link-check] status=ok"
