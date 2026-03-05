#!/usr/bin/env python3
"""Replay dead-letter alerts produced by pr7_alert_delivery.py."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
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


def replay_key(row: dict) -> str:
    fingerprint = str(row.get("fingerprint", "")).strip()
    if fingerprint and fingerprint != "unknown":
        return f"fp:{fingerprint}"
    channel = str(row.get("channel", "")).strip()
    message = str(row.get("message", "")).strip()
    digest = hashlib.sha256(f"{channel}\n{message}".encode("utf-8")).hexdigest()
    return f"msg:{digest}"


def load_receipts(path: Path) -> set[str]:
    done: set[str] = set()
    if not path.exists():
        return done
    for row in read_jsonl(path):
        key = str(row.get("replay_key", "")).strip()
        if key:
            done.add(key)
    return done


def append_receipt(path: Path, replay_key_value: str, channel: str, fingerprint: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(
            json.dumps(
                {
                    "replay_key": replay_key_value,
                    "channel": channel,
                    "fingerprint": fingerprint,
                },
                ensure_ascii=False,
            )
            + "\n"
        )


def acquire_lock(lock_path: Path) -> int | None:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    try:
        fd = os.open(str(lock_path), flags, 0o644)
    except FileExistsError:
        return None
    os.write(fd, str(os.getpid()).encode("utf-8"))
    return fd


def release_lock(lock_fd: int, lock_path: Path) -> None:
    try:
        os.close(lock_fd)
    finally:
        try:
            lock_path.unlink(missing_ok=True)
        except TypeError:
            if lock_path.exists():
                lock_path.unlink()


def main() -> int:
    ap = argparse.ArgumentParser(description="Replay PR7 dead-letter alerts")
    ap.add_argument("--dead-letter-file", default="run/pr7-alert-delivery/dead-letter.jsonl")
    ap.add_argument("--channel", choices=["slack", "telegram", "imessage"], help="override channel for all records")
    ap.add_argument("--max-items", type=int, default=100)
    ap.add_argument("--max-retries", type=int, default=3)
    ap.add_argument("--base-backoff-ms", type=int, default=500)
    ap.add_argument("--max-backoff-ms", type=int, default=8000)
    ap.add_argument("--global-retry-budget", type=int, default=int(os.environ.get("ALERT_NOTIFY_GLOBAL_RETRY_BUDGET", "0")))
    ap.add_argument("--global-retry-window-seconds", type=int, default=int(os.environ.get("ALERT_NOTIFY_GLOBAL_RETRY_WINDOW_SECONDS", "300")))
    ap.add_argument("--global-retry-budget-state-file", default=os.environ.get("ALERT_NOTIFY_GLOBAL_RETRY_BUDGET_STATE_FILE", "run/pr7-alert-delivery/retry-budget-state.json"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--dry-run-simulate-failures", type=int, default=0)
    ap.add_argument("--receipt-file", help="idempotency receipt jsonl file (default: <dead-letter>.replayed.jsonl)")
    ap.add_argument("--lock-file", help="process lock file (default: <dead-letter>.lock)")
    args = ap.parse_args()

    dead_letter_path = Path(args.dead_letter_file)
    receipt_path = Path(args.receipt_file) if args.receipt_file else Path(f"{dead_letter_path}.replayed.jsonl")
    lock_path = Path(args.lock_file) if args.lock_file else Path(f"{dead_letter_path}.lock")

    lock_fd = acquire_lock(lock_path)
    if lock_fd is None:
        print(f"[PR7][REPLAY][SKIP] another replay is running lock={lock_path}", file=sys.stderr)
        return 4

    try:
        rows = read_jsonl(dead_letter_path)
        if not rows:
            print(f"[PR7][REPLAY] no dead-letter entries: {dead_letter_path}")
            return 0

        already_replayed = load_receipts(receipt_path)
        limit = max(0, args.max_items)
        pending: list[dict] = []
        replayed = 0
        failed = 0
        dedup_skipped = 0

        for idx, row in enumerate(rows):
            if idx >= limit:
                pending.append(row)
                continue

            channel = args.channel or str(row.get("channel", "")).strip()
            message = str(row.get("message", "")).strip()
            fingerprint = str(row.get("fingerprint", "unknown"))
            key = replay_key(row)

            if key in already_replayed:
                dedup_skipped += 1
                print(f"[PR7][REPLAY][SKIP] replay_key={key} fingerprint={fingerprint} reason=already_replayed")
                continue

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
                global_retry_budget=max(0, args.global_retry_budget),
                global_retry_window_seconds=max(1, args.global_retry_window_seconds),
                global_retry_budget_state_file=args.global_retry_budget_state_file,
            )

            if ok:
                replayed += 1
                already_replayed.add(key)
                append_receipt(receipt_path, key, channel, fingerprint)
                print(f"[PR7][REPLAY][OK] fingerprint={fingerprint} replay_key={key} channel={channel} attempts={attempts}")
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
            f"[PR7][REPLAY] done replayed={replayed} dedup_skipped={dedup_skipped} failed={failed} "
            f"remaining={len(pending)} file={dead_letter_path} receipt={receipt_path}"
        )
        return 0 if failed == 0 else 3
    finally:
        release_lock(lock_fd, lock_path)


if __name__ == "__main__":
    raise SystemExit(main())
