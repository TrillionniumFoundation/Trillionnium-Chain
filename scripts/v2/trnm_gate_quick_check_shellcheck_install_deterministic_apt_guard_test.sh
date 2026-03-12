#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WF="$ROOT/.github/workflows/trnm-gate-quick-check.yml"

if [[ ! -f "$WF" ]]; then
  echo "[FAIL] missing workflow: $WF" >&2
  exit 1
fi

required_lines=(
  'retry 3 sudo apt-get -o DPkg::Lock::Timeout=60 -o Acquire::Retries=5 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o Dpkg::Use-Pty=0 -o APT::Color=0 update'
  'retry 3 sudo apt-get -o DPkg::Lock::Timeout=60 -o Acquire::Retries=5 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o Dpkg::Use-Pty=0 -o APT::Color=0 install -y --no-install-recommends shellcheck'
)

for line in "${required_lines[@]}"; do
  if ! grep -Fq -- "$line" "$WF"; then
    echo "[FAIL] missing deterministic shellcheck apt guard: $line" >&2
    exit 1
  fi
done

echo "[PASS] trnm-gate-quick-check keeps deterministic shellcheck apt install flags"
