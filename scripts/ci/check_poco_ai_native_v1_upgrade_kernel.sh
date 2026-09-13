#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"

# The v1 relation checker no longer trusts an opaque
# `admitted_by_frozen_v0_verifier` bit.  First execute the exact, independently
# maintained frozen-v0 fields-1-through-11 parser/crypto/composition gate whose
# sources are also content-hash-bound by the Python verifier.  That v0 gate
# deliberately returns no transition authority: fields 12--14 remain the
# explicit blocker to a complete cross-version contract.
bash "$repo_root/scripts/ci/check_poco_bft_v0_joint_handoff_schema.sh"
exec python3 "$repo_root/scripts/ci/check_poco_ai_native_v1_upgrade_kernel.py" "$@"
