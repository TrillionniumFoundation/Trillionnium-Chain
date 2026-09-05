#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WF="$ROOT/.github/workflows/rust-l1-nightly-health.yml"
PR6="$ROOT/scripts/v2/pr6_daily_security_summary.py"
CONS_SCRIPT="$ROOT/trillionnium/scripts/run_consensus_fault_matrix.sh"
ATTR_SCRIPT="$ROOT/trillionnium/scripts/nightly_attribution.sh"

python3 - "$WF" "$PR6" "$CONS_SCRIPT" "$ATTR_SCRIPT" <<'PY'
import pathlib
import sys

wf = pathlib.Path(sys.argv[1]).read_text(encoding='utf-8')
pr6 = pathlib.Path(sys.argv[2]).read_text(encoding='utf-8')
cons = pathlib.Path(sys.argv[3]).read_text(encoding='utf-8')
attr = pathlib.Path(sys.argv[4]).read_text(encoding='utf-8')

required_wf_snippets = [
    'CONSENSUS_FAULT_MATRIX_OUT="$hard_report"',
    'echo "hard_report=${hard_report}" >> "$GITHUB_OUTPUT"',
    'CONSENSUS_FAULT_MATRIX_OUT="$soft_report"',
    'echo "soft_report=${soft_report}" >> "$GITHUB_OUTPUT"',
    'NIGHTLY_ATTRIBUTION_OUT="$attribution_file"',
    'echo "attribution_file=${attribution_file}" >> "$GITHUB_OUTPUT"',
    'NIGHTLY_ATTRIBUTION_FILE="${{ steps.nightly_attribution.outputs.attribution_file }}"',
    'NIGHTLY_SUMMARY_FILE="${{ steps.render_nightly_summary.outputs.summary_file }}"',
]
for s in required_wf_snippets:
    if s not in wf:
        raise SystemExit(f"[FAIL] missing workflow binding snippet: {s}")

hard_block = wf.split('id: consensus_fault_hard', 1)[1].split('id: consensus_fault_soft', 1)[0]
soft_block = wf.split('id: consensus_fault_soft', 1)[1].split('name: Append consensus fault matrix', 1)[0]
for block, output_line, label in [
    (hard_block, 'echo "hard_report=${hard_report}" >> "$GITHUB_OUTPUT"', 'hard'),
    (soft_block, 'echo "soft_report=${soft_report}" >> "$GITHUB_OUTPUT"', 'soft'),
]:
    if block.index(output_line) >= block.index('./scripts/run_consensus_fault_matrix.sh'):
        raise SystemExit(f"[FAIL] {label} report output must be published before the matrix can fail")

for forbidden in [
    'ls -1t run/health/consensus-fault-matrix-',
    'ls -1t run/health/nightly-attribution-',
]:
    if forbidden in wf:
        raise SystemExit(f"[FAIL] workflow still uses unstable latest-artifact selection: {forbidden}")

for text, needle, label in [
    (pr6, 'os.environ.get("NIGHTLY_ATTRIBUTION_FILE")', 'pr6 env override for attribution'),
    (pr6, 'os.environ.get("NIGHTLY_SUMMARY_FILE")', 'pr6 env override for summary'),
    (pr6, 'os.environ.get("AUTO_ADAPTIVE_SUGGESTION_FILE")', 'pr6 env override for suggestion'),
    (cons, 'CONSENSUS_FAULT_MATRIX_OUT', 'consensus matrix explicit output override'),
    (attr, 'NIGHTLY_ATTRIBUTION_OUT', 'nightly attribution explicit output override'),
]:
    if needle not in text:
        raise SystemExit(f"[FAIL] missing {label}")

print('[PASS] nightly workflow binds critical artifacts explicitly instead of racing on latest-file discovery')
PY
