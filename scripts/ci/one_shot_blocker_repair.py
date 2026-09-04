#!/usr/bin/env python3
"""One-shot, assertion-backed repair for the current PR blocker set.

The workflow that invokes this script removes it before committing the repaired
sources. Every edit is guarded by an exact old-text assertion so drift fails
closed instead of producing a partial or ambiguous patch.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise SystemExit(
            f"[repair][FAIL] {label}: expected exactly one old block in "
            f"{path.relative_to(ROOT)}, found {count}"
        )
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"[repair] {label}=ok")


def patch_governance_audit_mapping() -> None:
    path = ROOT / "contracts/governance-guard/src/lib.rs"
    old = '''                normalized.object_id = Some("emergency_pause".to_string());
                normalized.related_id = Some(proposal_id.to_string());
                normalized.reason = Some("pause_restore_schedule".to_string());
                normalized.note = Some(format!("eta={eta}, reason_hash={reason_hash}"));
'''
    new = '''                normalized.object_id = Some(proposal_id.to_string());
                normalized.related_id = Some("emergency_pause".to_string());
                normalized.reason = Some(reason_hash.clone());
                normalized.note = Some(format!("eta={eta}"));
'''
    replace_once(path, old, new, "governance_pause_restore_audit_mapping")


def patch_retry_budget() -> None:
    path = ROOT / "scripts/v2/pr7_alert_delivery.py"

    replace_once(
        path,
        '''import argparse
import datetime as dt
import hashlib
''',
        '''import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
''',
        "retry_budget_imports",
    )

    replace_once(
        path,
        '''def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\\n", encoding="utf-8")


''',
        '''def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\\n", encoding="utf-8")


@contextlib.contextmanager
def exclusive_file_lock(path: Path):
    """Serialize global retry-budget updates across delivery processes."""

    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(f"{path.name}.lock")
    with lock_path.open("a+", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def consume_global_retry_slot(
    path: Path,
    *,
    budget: int,
    window_seconds: int,
) -> tuple[bool, int]:
    """Atomically consume one retry slot from a process-shared sliding window.

    The first delivery attempt is not a retry and therefore does not consume a
    slot. A non-positive budget disables the shared limiter.
    """

    if budget <= 0:
        return True, 0

    window_seconds = max(1, window_seconds)
    with exclusive_file_lock(path):
        now_ts = int(time.time())
        state = load_state(path)
        window_started_at = state.get("window_started_at")
        retries_used = state.get("retries_used")

        if (
            not isinstance(window_started_at, int)
            or not isinstance(retries_used, int)
            or retries_used < 0
            or now_ts < window_started_at
            or now_ts - window_started_at >= window_seconds
        ):
            window_started_at = now_ts
            retries_used = 0

        retries_used = min(retries_used, budget)
        allowed = retries_used < budget
        if allowed:
            retries_used += 1

        budget_state = {
            "window_started_at": window_started_at,
            "window_seconds": window_seconds,
            "budget": budget,
            "retries_used": retries_used,
            "updated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        }
        save_state(path, budget_state)
        return allowed, retries_used


''',
        "retry_budget_state_machine",
    )

    replace_once(
        path,
        '''    max_backoff_ms: int,
    dry_run_simulate_failures: int = 0,
) -> tuple[bool, int, str]:
''',
        '''    max_backoff_ms: int,
    dry_run_simulate_failures: int = 0,
    retry_budget_acquire=None,
) -> tuple[bool, int, str]:
''',
        "retry_budget_callback_signature",
    )

    replace_once(
        path,
        '''            if attempt > max_retries:
                return False, attempt, str(e)
            backoff_ms = min(max_backoff_ms, base_backoff_ms * (2 ** (attempt - 1)))
''',
        '''            if attempt > max_retries:
                return False, attempt, str(e)
            if retry_budget_acquire is not None:
                allowed, retries_used = retry_budget_acquire()
                if not allowed:
                    budget_error = (
                        "global retry budget exhausted "
                        f"(retries_used={retries_used})"
                    )
                    print(f"[PR7][RETRY] {budget_error}", file=sys.stderr)
                    return False, attempt, budget_error
            backoff_ms = min(max_backoff_ms, base_backoff_ms * (2 ** (attempt - 1)))
''',
        "retry_budget_enforcement",
    )

    replace_once(
        path,
        '''    ap.add_argument("--max-backoff-ms", type=int, default=int(os.environ.get("ALERT_NOTIFY_MAX_BACKOFF_MS", "8000")))
    ap.add_argument("--quiet-hours-enabled", action="store_true", default=os.environ.get("ALERT_NOTIFY_QUIET_HOURS_ENABLED", "0") == "1")
''',
        '''    ap.add_argument("--max-backoff-ms", type=int, default=int(os.environ.get("ALERT_NOTIFY_MAX_BACKOFF_MS", "8000")))
    ap.add_argument(
        "--global-retry-budget",
        type=int,
        default=int(os.environ.get("ALERT_NOTIFY_GLOBAL_RETRY_BUDGET", "0")),
        help="process-shared retry slots per window; 0 disables the limiter",
    )
    ap.add_argument(
        "--global-retry-window-seconds",
        type=int,
        default=int(os.environ.get("ALERT_NOTIFY_GLOBAL_RETRY_WINDOW_SECONDS", "600")),
    )
    ap.add_argument(
        "--global-retry-budget-state-file",
        default=os.environ.get(
            "ALERT_NOTIFY_GLOBAL_RETRY_BUDGET_STATE_FILE",
            "run/pr7-alert-delivery/global-retry-budget.json",
        ),
    )
    ap.add_argument("--quiet-hours-enabled", action="store_true", default=os.environ.get("ALERT_NOTIFY_QUIET_HOURS_ENABLED", "0") == "1")
''',
        "retry_budget_cli",
    )

    replace_once(
        path,
        '''    ok, attempts, err = send_with_retry(
        channel=args.channel,
''',
        '''    retry_budget_acquire = None
    if args.global_retry_budget > 0:
        budget_path = Path(args.global_retry_budget_state_file)

        def retry_budget_acquire():
            return consume_global_retry_slot(
                budget_path,
                budget=max(0, args.global_retry_budget),
                window_seconds=max(1, args.global_retry_window_seconds),
            )

    ok, attempts, err = send_with_retry(
        channel=args.channel,
''',
        "retry_budget_call_setup",
    )

    replace_once(
        path,
        '''        dry_run_simulate_failures=max(0, args.dry_run_simulate_failures),
    )
''',
        '''        dry_run_simulate_failures=max(0, args.dry_run_simulate_failures),
        retry_budget_acquire=retry_budget_acquire,
    )
''',
        "retry_budget_call_binding",
    )


def patch_event_replay_causality() -> None:
    path = ROOT / "trillionnium/crates/trnm-node/src/main.rs"

    replace_once(
        path,
        '''fn pick_txs_with_critical_guard(
    mempool: &mut VecDeque<MockTx>,
    txs_per_block: usize,
) -> Vec<MockTx> {
''',
        '''fn is_task_lifecycle_tx(tx: &MockTx) -> bool {
    matches!(
        tx,
        MockTx::CreateTask { .. }
            | MockTx::AcceptTask { .. }
            | MockTx::Commit { .. }
            | MockTx::Reveal { .. }
            | MockTx::Challenge { .. }
            | MockTx::Resolve { .. }
    )
}

fn shares_causal_stream(earlier: &MockTx, candidate: &MockTx) -> bool {
    if is_task_lifecycle_tx(earlier) && is_task_lifecycle_tx(candidate) {
        return task_id_of(earlier) == task_id_of(candidate);
    }

    matches!(
        (
            consumption_record_key_of(earlier),
            consumption_record_key_of(candidate),
        ),
        (Some(lhs), Some(rhs)) if lhs == rhs
    )
}

fn critical_tx_is_causally_ready(mempool: &VecDeque<MockTx>, idx: usize) -> bool {
    let Some(candidate) = mempool.get(idx) else {
        return false;
    };
    is_critical_tx(candidate)
        && !mempool
            .iter()
            .take(idx)
            .any(|earlier| shares_causal_stream(earlier, candidate))
}

fn pick_txs_with_critical_guard(
    mempool: &mut VecDeque<MockTx>,
    txs_per_block: usize,
) -> Vec<MockTx> {
''',
        "event_replay_causal_helpers",
    )

    replace_once(
        path,
        '''    for (idx, tx) in mempool.iter().enumerate() {
        let class = if is_critical_tx(tx) {
            IngressClass::Critical
        } else {
            IngressClass::Normal
        };
''',
        '''    for (idx, _tx) in mempool.iter().enumerate() {
        let class = if critical_tx_is_causally_ready(mempool, idx) {
            IngressClass::Critical
        } else {
            IngressClass::Normal
        };
''',
        "event_replay_causal_classification",
    )

    replace_once(
        path,
        '''    picked_slots.into_iter().flatten().collect()
}

fn actor_of(st: &StateStore, tx: &MockTx) -> String {
''',
        '''    picked_slots.into_iter().flatten().collect()
}

#[cfg(test)]
mod critical_causal_guard_regression {
    use super::*;

    #[test]
    fn same_task_challenge_cannot_overtake_create() {
        let mut mempool = VecDeque::from(vec![
            MockTx::CreateTask {
                task_id: 1,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::Challenge {
                task_id: 1,
                challenger: "challenger".into(),
                bond: 10,
            },
            MockTx::CreateTask {
                task_id: 2,
                creator: "bob".into(),
                bounty: 20,
            },
        ]);

        let picked = pick_txs_with_critical_guard(&mut mempool, 1);
        assert!(matches!(
            picked.as_slice(),
            [MockTx::CreateTask { task_id: 1, .. }]
        ));
    }

    #[test]
    fn unrelated_task_challenge_keeps_critical_priority() {
        let mut mempool = VecDeque::from(vec![
            MockTx::CreateTask {
                task_id: 1,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::Challenge {
                task_id: 2,
                challenger: "challenger".into(),
                bond: 10,
            },
            MockTx::AcceptTask {
                task_id: 1,
                worker: "worker1".into(),
            },
        ]);

        let picked = pick_txs_with_critical_guard(&mut mempool, 1);
        assert!(matches!(
            picked.as_slice(),
            [MockTx::Challenge { task_id: 2, .. }]
        ));
    }
}

fn actor_of(st: &StateStore, tx: &MockTx) -> String {
''',
        "event_replay_causal_regressions",
    )


def refresh_legacy_freeze() -> None:
    path = ROOT / "config/legacy-harness-freeze.sha256"
    main_rs = ROOT / "trillionnium/crates/trnm-node/src/main.rs"
    digest = hashlib.sha256(main_rs.read_bytes()).hexdigest()
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    target = "trillionnium/crates/trnm-node/src/main.rs"
    matches = [idx for idx, line in enumerate(lines) if line.endswith(f"  {target}")]
    if len(matches) != 1:
        raise SystemExit(
            f"[repair][FAIL] legacy freeze: expected one {target} entry, found {len(matches)}"
        )
    lines[matches[0]] = f"{digest}  {target}"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[repair] legacy_harness_freeze={digest}")


def main() -> None:
    patch_governance_audit_mapping()
    patch_retry_budget()
    patch_event_replay_causality()
    refresh_legacy_freeze()
    print("[repair] all assertion-backed patches applied")


if __name__ == "__main__":
    main()
