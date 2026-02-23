#!/usr/bin/env python3
"""Replay dead-letter alerts produced by pr7_alert_delivery.py."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pr7_alert_delivery import send_with_retry


def read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as f:
        for i, raw in enumerate(f, start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"[PR7][REPLAY][WARN] skip invalid json line={i}: {e}", file=sys.stderr)
                continue
            if isinstance(obj, dict):
                rows.append(obj)
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="Replay PR7 dead-letter alerts")
    ap.add_argument("--dead-letter-file", default="run/pr7-alert-delivery/dead-letter.jsonl")
    ap.add_argument("--channel", choices=["slack", "telegram", "imessage"], help="override channel for all records")
    ap.add_argument("--max-items", type=int, default=100)
    ap.add_argument("--max-retries", type=int, default=3)
    ap.add_argument("--base-backoff-ms", type=int, default=500)
    ap.add_argument("--max-backoff-ms", type=int, default=8000)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--dry-run-simulate-failures", type=int, default=0)
    args = ap.parse_args()

    dead_letter_path = Path(args.dead_letter_file)
    rows = read_jsonl(dead_letter_path)
    if not rows:
        print(f"[PR7][REPLAY] no dead-letter entries: {dead_letter_path}")
        return 0

    limit = max(0, args.max_items)
    pending: list[dict] = []
    replayed = 0
    failed = 0

    for idx, row in enumerate(rows):
        if idx >= limit:
            pending.append(row)
            continue

        channel = args.channel or str(row.get("channel", "")).strip()
        message = str(row.get("message", "")).strip()
        fingerprint = str(row.get("fingerprint", "unknown"))

        if not channel or not message:
            row["replay_error"] = "missing channel or message"
            pending.append(row)
            failed += 1
            print(f"[PR7][REPLAY][FAIL] fingerprint={fingerprint} reason=missing channel/message", file=sys.stderr)
            continue

        ok, attempts, err = send_with_retry(
            channel=channel,
            text=message,
            dry_run=args.dry_run,
            max_retries=max(0, args.max_retries),
            base_backoff_ms=max(1, args.base_backoff_ms),
            max_backoff_ms=max(1, args.max_backoff_ms),
            dry_run_simulate_failures=max(0, args.dry_run_simulate_failures),
        )

        if ok:
            replayed += 1
            print(f"[PR7][REPLAY][OK] fingerprint={fingerprint} channel={channel} attempts={attempts}")
        else:
            row["replay_error"] = err
            row["replay_attempts"] = attempts
            pending.append(row)
            failed += 1
            print(
                f"[PR7][REPLAY][FAIL] fingerprint={fingerprint} channel={channel} "
                f"attempts={attempts} err={err}",
                file=sys.stderr,
            )

    write_jsonl(dead_letter_path, pending)
    print(
        f"[PR7][REPLAY] done replayed={replayed} failed={failed} "
        f"remaining={len(pending)} file={dead_letter_path}"
    )
    return 0 if failed == 0 else 3


if __name__ == "__main__":
    raise SystemExit(main())
