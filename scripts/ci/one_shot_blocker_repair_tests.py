#!/usr/bin/env python3
"""Update legacy scheduler regressions after the causal-ordering repair."""

from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAIN = ROOT / "trillionnium/crates/trnm-node/src/main.rs"
FREEZE = ROOT / "config/legacy-harness-freeze.sha256"


def replace_once(old: str, new: str, label: str) -> None:
    text = MAIN.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(
            f"[repair][FAIL] {label}: expected exactly one old block, found {count}"
        )
    MAIN.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"[repair] {label}=ok")


def main() -> None:
    replace_once(
        "fn critical_txs_are_selected_even_when_normal_queue_is_long() {",
        "fn critical_txs_wait_for_same_task_prerequisites_when_normal_queue_is_long() {",
        "rename_same_task_priority_regression",
    )
    replace_once(
        '''        assert!(matches!(picked[0], MockTx::Challenge { .. }));
        assert!(matches!(picked[1], MockTx::CreateTask { task_id: 1, .. }));
        assert_eq!(mempool.len(), 4);
''',
        '''        assert!(matches!(picked[0], MockTx::CreateTask { task_id: 1, .. }));
        assert!(matches!(picked[1], MockTx::AcceptTask { task_id: 1, .. }));
        assert_eq!(mempool.len(), 4);
''',
        "same_task_priority_expectation",
    )
    replace_once(
        '''        assert!(matches!(picked[0], MockTx::Challenge { .. }));
        assert!(matches!(picked[1], MockTx::CreateTask { .. }));
        assert!(matches!(picked[2], MockTx::Resolve { .. }));
''',
        '''        assert!(matches!(picked[0], MockTx::CreateTask { .. }));
        assert!(matches!(picked[1], MockTx::Challenge { .. }));
        assert!(matches!(picked[2], MockTx::Resolve { .. }));
''',
        "lane_fairness_causal_expectation",
    )
    replace_once(
        '''        assert!(matches!(picked[0], MockTx::Challenge { .. }));
        assert!(matches!(picked[1], MockTx::CreateTask { task_id: 21, .. }));
        assert!(matches!(picked[2], MockTx::AcceptTask { .. }));
''',
        '''        assert!(matches!(picked[0], MockTx::CreateTask { task_id: 21, .. }));
        assert!(matches!(picked[1], MockTx::AcceptTask { task_id: 21, .. }));
        assert!(matches!(picked[2], MockTx::Challenge { task_id: 21, .. }));
''',
        "scanned_prefix_causal_expectation",
    )

    digest = hashlib.sha256(MAIN.read_bytes()).hexdigest()
    lines = FREEZE.read_text(encoding="utf-8").splitlines()
    target = "trillionnium/crates/trnm-node/src/main.rs"
    indexes = [idx for idx, line in enumerate(lines) if line.endswith(f"  {target}")]
    if len(indexes) != 1:
        raise SystemExit(
            f"[repair][FAIL] legacy freeze: expected one {target} entry, found {len(indexes)}"
        )
    lines[indexes[0]] = f"{digest}  {target}"
    FREEZE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[repair] legacy_harness_freeze={digest}")


if __name__ == "__main__":
    main()
