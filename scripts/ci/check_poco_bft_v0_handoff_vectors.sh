#!/bin/sh
set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
export PYTHONDONTWRITEBYTECODE=1
exec python3 "$REPO_ROOT/scripts/ci/check_poco_bft_v0_handoff_vectors.py" "$@"
