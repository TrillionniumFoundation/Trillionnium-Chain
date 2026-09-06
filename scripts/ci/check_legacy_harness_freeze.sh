#!/usr/bin/env bash
set -euo pipefail

# Compatibility entrypoint retained for existing workflow references.
# The actual policy is the native-consensus-only gate.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/check_self_consensus_only.sh"
