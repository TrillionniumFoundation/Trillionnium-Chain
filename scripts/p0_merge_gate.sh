#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Mainline merge gate: full P0 + P1 reconcile + reexec smoke.
# Any failing step blocks merge by non-zero exit code.
"$ROOT/scripts/p0_acceptance.sh" --with-p1 --with-reexec "$@"
