#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET="$ROOT/trillionnium-rust/scripts/run_local_release_evidence.sh"

if [[ ! -f "$TARGET" ]]; then
  echo "[FAIL] missing target script: $TARGET" >&2
  exit 1
fi

if ! grep -q 'TRNM_CHALLENGE_REEXEC_ENTRY' "$TARGET"; then
  echo "[FAIL] expected deterministic override env TRNM_CHALLENGE_REEXEC_ENTRY" >&2
  exit 1
fi

if grep -q 'find "\$ROOT/scripts"' "$TARGET" || grep -q 'find "\$repo_root/scripts"' "$TARGET"; then
  echo "[FAIL] nondeterministic find-based entry discovery still present" >&2
  exit 1
fi

if ! grep -q 'challenge_reexec_entry=' "$TARGET"; then
  echo "[FAIL] expected summary to record resolved challenge reexec entry" >&2
  exit 1
fi

if ! grep -Fq "TRNM_CHALLENGE_REEXEC_ENTRY='\${replay_challenge_entry}'" "$TARGET"; then
  echo "[FAIL] expected replay_command to pin deterministic challenge reexec entry" >&2
  exit 1
fi

echo "[PASS] run_local_release_evidence uses deterministic challenge entry selection and replay pinning"
