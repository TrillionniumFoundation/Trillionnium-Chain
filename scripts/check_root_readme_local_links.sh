#!/usr/bin/env bash
set -euo pipefail

README_PATH="${1:-README.md}"

if [[ ! -f "$README_PATH" ]]; then
  echo "[readme-link-check][FAIL] README not found: $README_PATH" >&2
  exit 2
fi

if ! grep -q '[^[:space:]]' "$README_PATH"; then
  echo "[readme-link-check][FAIL] README is empty or whitespace-only: $README_PATH" >&2
  exit 2
fi

# The repository entrypoint must remain a useful entrypoint, not a token stub.
if [[ "$README_PATH" == "README.md" ]]; then
  line_count="$(wc -l < "$README_PATH" | tr -d '[:space:]')"
  if [[ ! "$line_count" =~ ^[0-9]+$ ]] || (( line_count < 80 )); then
    echo "[readme-link-check][FAIL] root README is unexpectedly short: ${line_count:-unknown} lines" >&2
    exit 2
  fi

  required_headings=(
    '# Trillionnium Chain (TRNM)'
    '## Repository map'
    '## Maturity and scope'
    '## Build and test'
    '## Module documentation'
    '## Documentation entry points'
    '## Contribution and evidence rules'
    '## Security'
  )
  for heading in "${required_headings[@]}"; do
    if ! grep -Fqx "$heading" "$README_PATH"; then
      echo "[readme-link-check][FAIL] root README missing required heading: $heading" >&2
      exit 2
    fi
  done
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

if [[ "$checked" -eq 0 ]]; then
  echo "[readme-link-check][FAIL] no relative links were checked" >&2
  exit 1
fi

if [[ "$missing" -ne 0 ]]; then
  exit 1
fi

echo "[readme-link-check] status=ok"
