#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"
if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
  echo "DA-FULLREP-V1 candidate: FAIL: clean snapshot required" >&2
  exit 1
fi
export PYTHONDONTWRITEBYTECODE=1
exec python3 -B scripts/ci/check_da_fullrep_model_v1.py
