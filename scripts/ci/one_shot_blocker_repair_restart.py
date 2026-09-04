#!/usr/bin/env python3
"""Make the restart drill kill only after recoverable checkpoint persistence."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "trillionnium/scripts/check_bft_restart_recovery.sh"


def main() -> None:
    text = PATH.read_text(encoding="utf-8")
    old = '''    --bft-fault-rounds 1 \\
    --bft-wal-dir "$WAL_DIR"'''
    new = '''    --bft-fault-rounds 1 \\
    --bft-checkpoint-interval 1 \\
    --bft-wal-dir "$WAL_DIR"'''
    count = text.count(old)
    if count != 2:
        raise SystemExit(
            f"[repair][FAIL] restart checkpoint binding: expected 2 command blocks, found {count}"
        )
    PATH.write_text(text.replace(old, new), encoding="utf-8")
    print("[repair] restart_checkpoint_interval=1")


if __name__ == "__main__":
    main()
