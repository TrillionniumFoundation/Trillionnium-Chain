#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; exit 1; }
info() { echo "[INFO] $1"; }

info "Running PoUW V1 release gate (automatable checks)"

go test ./... -count=1 >/tmp/trnm-release-gate-go-test.log 2>&1 || {
  cat /tmp/trnm-release-gate-go-test.log >&2
  fail "go test ./..."
}
pass "go test ./... -count=1"

make smoke-pouw-e2e >/tmp/trnm-release-gate-smoke.log 2>&1 || {
  cat /tmp/trnm-release-gate-smoke.log >&2
  fail "make smoke-pouw-e2e"
}
pass "make smoke-pouw-e2e"

make check-pouw-cmds >/tmp/trnm-release-gate-cmds.log 2>&1 || {
  cat /tmp/trnm-release-gate-cmds.log >&2
  fail "make check-pouw-cmds"
}
pass "make check-pouw-cmds"

if ./tools/smoke_pouw_cli_flow.sh >/tmp/trnm-release-gate-cli.log 2>&1; then
  pass "./tools/smoke_pouw_cli_flow.sh"
else
  cat /tmp/trnm-release-gate-cli.log >&2
  fail "./tools/smoke_pouw_cli_flow.sh"
fi

echo
echo "=== MANUAL CHECKS REQUIRED ==="
echo "[TODO] Review docs/OPERATOR_CHECKLIST_POUW_V1.md sections B-F"
echo "[TODO] Confirm authority ownership and governance policy"
echo "[TODO] Record one independent operator replay"
echo
echo "Release gate completed (automatable checks passed)."
