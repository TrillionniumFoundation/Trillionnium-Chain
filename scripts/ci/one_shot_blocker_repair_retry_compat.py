#!/usr/bin/env python3
"""Complete the PR-7 retry-budget CLI and delivery-audit contract."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "scripts/v2/pr7_alert_delivery.py"


def replace_once(old: str, new: str, label: str) -> None:
    text = PATH.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(
            f"[repair][FAIL] {label}: expected exactly one old block, found {count}"
        )
    PATH.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"[repair] {label}=ok")


def main() -> None:
    replace_once(
        '''def append_dead_letter(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\\n")


def main() -> int:
''',
        '''def append_dead_letter(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\\n")


def append_delivery_audit(path: Path, record: dict) -> None:
    """Append one valid JSONL record under a process-shared file lock."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with exclusive_file_lock(path):
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\\n")
            f.flush()
            os.fsync(f.fileno())


def parse_dry_run_fail_channels(raw: str) -> set[str]:
    channels = {item.strip().lower() for item in raw.split(",") if item.strip()}
    supported = {"slack", "telegram", "imessage"}
    unknown = sorted(channels - supported)
    if unknown:
        raise ValueError(f"unsupported dry-run fail channel(s): {','.join(unknown)}")
    return channels


def main() -> int:
''',
        "retry_compat_audit_helpers",
    )

    replace_once(
        '''    ap.add_argument("--state-file", default=os.environ.get("ALERT_NOTIFY_STATE_FILE", "run/pr7-alert-delivery/state.json"))
    ap.add_argument("--dead-letter-file", default=os.environ.get("ALERT_NOTIFY_DEAD_LETTER_FILE", "run/pr7-alert-delivery/dead-letter.jsonl"))
    ap.add_argument("--min-level", default=os.environ.get("ALERT_NOTIFY_MIN_LEVEL", "WARN"))
''',
        '''    ap.add_argument("--state-file", default=os.environ.get("ALERT_NOTIFY_STATE_FILE", "run/pr7-alert-delivery/state.json"))
    ap.add_argument("--dead-letter-file", default=os.environ.get("ALERT_NOTIFY_DEAD_LETTER_FILE", "run/pr7-alert-delivery/dead-letter.jsonl"))
    ap.add_argument(
        "--audit-file",
        default=os.environ.get(
            "ALERT_NOTIFY_AUDIT_FILE",
            "run/pr7-alert-delivery/audit.jsonl",
        ),
        help="append-only JSONL delivery-attempt audit log",
    )
    ap.add_argument("--min-level", default=os.environ.get("ALERT_NOTIFY_MIN_LEVEL", "WARN"))
''',
        "retry_compat_audit_cli",
    )

    replace_once(
        '''    ap.add_argument("--dry-run", action="store_true", default=os.environ.get("DRY_RUN", "0") == "1")
    ap.add_argument(
        "--dry-run-simulate-failures",
''',
        '''    ap.add_argument("--dry-run", action="store_true", default=os.environ.get("DRY_RUN", "0") == "1")
    ap.add_argument(
        "--dry-run-fail-channels",
        default=os.environ.get("ALERT_NOTIFY_DRY_RUN_FAIL_CHANNELS", ""),
        help="comma-separated channels forced to fail in dry-run mode",
    )
    ap.add_argument(
        "--dry-run-simulate-failures",
''',
        "retry_compat_fail_channels_cli",
    )

    replace_once(
        '''    args = ap.parse_args()

    report_path = Path(args.report)
''',
        '''    args = ap.parse_args()

    try:
        dry_run_fail_channels = parse_dry_run_fail_channels(args.dry_run_fail_channels)
    except ValueError as e:
        print(f"[PR7][FAIL] {e}", file=sys.stderr)
        return 2

    report_path = Path(args.report)
''',
        "retry_compat_fail_channels_parse",
    )

    replace_once(
        '''    dry_run_simulate_failures: int = 0,
    retry_budget_acquire=None,
) -> tuple[bool, int, str]:
''',
        '''    dry_run_simulate_failures: int = 0,
    dry_run_force_failure: bool = False,
    retry_budget_acquire=None,
) -> tuple[bool, int, str]:
''',
        "retry_compat_callback_signature",
    )

    replace_once(
        '''            if dry_run and attempt <= dry_run_simulate_failures:
                raise RuntimeError(f"dry-run injected failure at attempt={attempt}")
''',
        '''            if dry_run and (dry_run_force_failure or attempt <= dry_run_simulate_failures):
                reason = "forced channel failure" if dry_run_force_failure else "injected failure"
                raise RuntimeError(f"dry-run {reason} at attempt={attempt}")
''',
        "retry_compat_forced_failure",
    )

    replace_once(
        '''        dry_run_simulate_failures=max(0, args.dry_run_simulate_failures),
        retry_budget_acquire=retry_budget_acquire,
    )

    if not ok:
''',
        '''        dry_run_simulate_failures=max(0, args.dry_run_simulate_failures),
        dry_run_force_failure=args.dry_run and args.channel in dry_run_fail_channels,
        retry_budget_acquire=retry_budget_acquire,
    )

    append_delivery_audit(
        Path(args.audit_file),
        {
            "at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "attempts": attempts,
            "channel": args.channel,
            "class_fingerprint": class_fp,
            "dry_run": args.dry_run,
            "event": "delivery_attempt",
            "fingerprint": exact_fp,
            "last_error": err or None,
            "level": level,
            "outcome": "sent" if ok else "failed",
            "report_path": str(report_path),
        },
    )

    if not ok:
''',
        "retry_compat_audit_binding",
    )

    print("[repair] PR7 retry compatibility and audit contract complete")


if __name__ == "__main__":
    main()
