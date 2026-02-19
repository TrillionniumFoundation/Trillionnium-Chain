#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Mainline merge gate:
# 1) P0 acceptance bundle (with reconcile + reexec smoke)
# 2) P1 negative suite + optional rust sidecar verification (default ON)

WITH_RUST_VERIFY="${WITH_RUST_VERIFY:-1}"

"$ROOT/scripts/p0_acceptance.sh" --with-p1 --with-reexec "$@"
WITH_RUST_VERIFY="$WITH_RUST_VERIFY" "$ROOT/scripts/p1_negative_suite.sh"
