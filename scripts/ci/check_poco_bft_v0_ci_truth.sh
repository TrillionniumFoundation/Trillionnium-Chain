#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel)
# Exercise the cold-cache installer contract before the real compiler install.
python3 -B "$root/scripts/ci/test_pinned_protoc_installer_v1.py"
python3 "$root/scripts/ci/check_native_consensus_only.py"
# Validate the real unconditional run block and its full commands, not a
# filename appearing in comments, an echo or an unrelated step.
python3 "$root/scripts/ci/check_native_workflow_contract_v1.py"
printf '%s\n' '{"schema":"trnm-native-ci-truth-v1","result":"PASS"}'
