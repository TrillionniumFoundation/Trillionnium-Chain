#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

for n in 1 2 3; do
  pidf="run/node${n}.pid"
  if [[ -f "$pidf" ]]; then
    pid="$(cat "$pidf")"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" || true
      echo "stopped node${n} pid=$pid"
    fi
    rm -f "$pidf"
  fi
done

echo "devnet stopped"
