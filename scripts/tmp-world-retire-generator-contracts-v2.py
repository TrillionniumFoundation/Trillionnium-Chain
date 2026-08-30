#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit("usage: tmp-world-retire-generator-contracts-v2.py <world-root>")

root = Path(sys.argv[1]).resolve()
crate = root / "trillionnium/crates/trnm-game-server"

boundary_test = r'''const GAME_SERVER_SOURCE: &str = include_str!("../src/lib.rs");
const SETTLEMENT_WORKER_ENTRYPOINT: &str = include_str!("../src/settlement_worker.rs");
const SETTLEMENT_WORKER_LEGACY_SOURCE: &str = include_str!("../src/settlement_worker_legacy.rs");
const SETTLEMENT_WORKER_RUNTIME_SOURCE: &str =
    include_str!("../src/settlement_worker_runtime_v2.rs");

fn complete_settlement_worker_source() -> String {
    [
        SETTLEMENT_WORKER_ENTRYPOINT,
        SETTLEMENT_WORKER_LEGACY_SOURCE,
        SETTLEMENT_WORKER_RUNTIME_SOURCE,
    ]
    .join("\n")
}

#[test]
fn game_server_does_not_execute_terminal_economy_settlement() {
    assert!(!GAME_SERVER_SOURCE.contains("reconcile_economy(&state.cex"));
    assert!(!GAME_SERVER_SOURCE.contains("settle_pending_matches(&settlement_state"));
    assert!(GAME_SERVER_SOURCE.contains(
        "terminal settlement is owned by trnm-settlement-worker; in-process settlement is prohibited"
    ));
}

#[test]
fn both_runtime_entrypoints_register_the_complete_settlement_migration_chain() {
    let worker_source = complete_settlement_worker_source();
    for marker in [
        "0016_online_settlement_outbox_v1",
        "0017_online_settlement_worker_runtime_v1",
        "0018_online_settlement_operator_controls_v1",
        "0019_online_settlement_quarantine_v1",
    ] {
        assert!(
            GAME_SERVER_SOURCE.contains(marker),
            "direct game server lost {marker}"
        );
        assert!(
            worker_source.contains(marker),
            "direct settlement worker lost {marker}"
        );
    }
}

#[test]
fn directly_compiled_runtime_has_no_build_output_dependency() {
    for source in [GAME_SERVER_SOURCE, SETTLEMENT_WORKER_ENTRYPOINT] {
        assert!(!source.contains("OUT_DIR"));
    }
    assert!(SETTLEMENT_WORKER_ENTRYPOINT.contains("settlement_worker_legacy.rs"));
    assert!(SETTLEMENT_WORKER_ENTRYPOINT.contains("settlement_worker_runtime_v2.rs"));
}
'''

boundary_script = r'''#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-full}"
[[ "$MODE" == "full" || "$MODE" == "scan-only" ]] \
  || { echo "usage: $0 [full|scan-only]" >&2; exit 2; }

python3 - "$ROOT_DIR" "$MODE" <<'PY'
from __future__ import annotations

import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1]).resolve()
mode = sys.argv[2]


def fail(message: str) -> None:
    raise SystemExit(f"TRNM settlement transaction boundary: FAIL: {message}")


def read(relative: str) -> str:
    path = root / relative
    if not path.is_file() or path.stat().st_size == 0:
        fail(f"missing required source: {relative}")
    return path.read_text(encoding="utf-8")


def require(source: str, markers: tuple[str, ...], label: str) -> None:
    missing = [marker for marker in markers if marker not in source]
    if missing:
        fail(f"{label} lost markers: {missing}")


def function_body(source: str, name: str) -> str:
    match = re.search(
        rf"(?m)^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?(?:async[ \t]+)?fn[ \t]+{re.escape(name)}\b[^{{;]*\{{",
        source,
    )
    if match is None:
        fail(f"missing settlement phase function {name}")
    depth = 0
    in_string = False
    in_char = False
    escaped = False
    for index in range(match.end() - 1, len(source)):
        char = source[index]
        if in_string or in_char:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif in_string and char == '"':
                in_string = False
            elif in_char and char == "'":
                in_char = False
            continue
        if char == '"':
            in_string = True
        elif char == "'":
            in_char = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[match.start() : index + 1]
    fail(f"unterminated settlement phase function {name}")
    raise AssertionError


entry = read("trillionnium/crates/trnm-game-server/src/lib.rs")
worker_entry = read("trillionnium/crates/trnm-game-server/src/settlement_worker.rs")
worker_legacy = read("trillionnium/crates/trnm-game-server/src/settlement_worker_legacy.rs")
worker_runtime = read("trillionnium/crates/trnm-game-server/src/settlement_worker_runtime_v2.rs")
worker = worker_legacy + "\n" + worker_runtime
cex = read("trillionnium/crates/trnm-game-server/src/cex.rs")
signer = read("trillionnium/crates/trnm-game-server/src/bin/trnm-entitlement-signer.rs")
outbox = read("trillionnium/crates/trnm-game-server/migrations/0016_online_settlement_outbox_v1.sql")
worker_sql = read("trillionnium/crates/trnm-game-server/migrations/0017_online_settlement_worker_runtime_v1.sql")
operator_sql = read("trillionnium/crates/trnm-game-server/migrations/0018_online_settlement_operator_controls_v1.sql")
boundary_test = read("trillionnium/crates/trnm-game-server/tests/settlement_game_server_boundary.rs")
capture_test = read("trillionnium/crates/trnm-game-server/tests/settlement_capture_commit_boundary.rs")
operator_test = read("trillionnium/crates/trnm-game-server/tests/settlement_operator_controls_database.rs")
workflow = read(".github/workflows/trnm-settlement-fencing.yml")

require(
    entry,
    (
        "terminal settlement is owned by trnm-settlement-worker",
        "0016_online_settlement_outbox_v1",
        "0017_online_settlement_worker_runtime_v1",
        "0018_online_settlement_operator_controls_v1",
        "0019_online_settlement_quarantine_v1",
    ),
    "direct game-server source",
)
require(
    worker_entry,
    (
        'include!("settlement_worker_legacy.rs")',
        'include!("settlement_worker_runtime_v2.rs")',
        "run_v2 as run",
    ),
    "direct settlement-worker entrypoint",
)
if "OUT_DIR" in entry or "OUT_DIR" in worker_entry:
    fail("direct runtime source depends on build output")
if "reconcile_economy(&state.cex" in entry:
    fail("compiled game-server reintroduced synchronous CEX settlement")
if "settle_pending_matches(&settlement_state" in entry:
    fail("compiled game-server reintroduced in-process terminal settlement")

transaction_markers = (".begin()", ".begin(\n", "Transaction<", "for update", "for update skip locked")
remote_markers = (".authorize_settlement_intent(", ".submit_authorized_settlement_intent(")
for phase in ("capture_match", "apply_capture"):
    body = function_body(worker, phase)
    if not any(marker in body for marker in transaction_markers):
        fail(f"{phase} no longer owns its short PostgreSQL transaction")
    if any(marker in body for marker in remote_markers):
        fail(f"{phase} performs signer/CEX transport under a transaction")

execute = function_body(worker, "process_claimed_job")
if any(marker in execute for marker in transaction_markers):
    fail("process_claimed_job owns a PostgreSQL transaction")
require(execute, remote_markers, "transaction-free execute phase")
require(
    worker,
    (
        "expected_campaign_state_hash",
        "authorization_request_id",
        "entitlement_issued_at_epoch",
        "entitlement_expires_at_epoch",
        "entitlement_nonce",
        "campaign_applied_at",
        "ReceiptProgressionClass::RecoverableHold",
    ),
    "settlement worker durable contract",
)

if mode == "full":
    require(
        cex,
        (
            "async fn lookup_signer_receipt",
            "async fn lookup_authorized_settlement_receipt",
            "CEX_SETTLEMENT_RECEIPT_LOOKUP_PATH",
            "Err(SETTLEMENT_OUTBOX_REQUIRED.to_string())",
        ),
        "CEX recovery client",
    )
    if "blocking_client" in cex or "reqwest::blocking" in cex:
        fail("CEX client reintroduced blocking HTTP transport")
    require(signer, ('"/v1/signer/receipts/:request_id"',), "signer receipt route")

    lower_outbox = outbox.lower()
    if "on delete restrict" not in lower_outbox or "on delete cascade" in lower_outbox:
        fail("settlement evidence foreign keys are not restrictive")
    require(
        worker_sql,
        (
            "trnm_online_remote_request_id_v1",
            "pg_catalog.sha256(",
            "trnm_online_claim_settlement_job_v2",
            "trnm_online_store_settlement_authorization_v1",
            "trnm_online_begin_settlement_remote_attempt_v1",
            "trnm_online_complete_settlement_job_v1",
            "trnm_online_retry_settlement_job_v1",
            "trnm_online_dead_letter_settlement_job_v1",
            "lease_expires_at > pg_catalog.clock_timestamp()",
            "when job.state = 'succeeded' then 'pending_apply'",
            "when job.campaign_applied_at is not null then 'applied'",
            "trnm_online_settlement_metrics_v1",
        ),
        "worker migration",
    )
    normalized_operator = " ".join(operator_sql.lower().split())
    require(
        normalized_operator,
        (
            "trnm_online_settlement_operator_replay",
            "trnm_online_settlement_operator_replay_requests",
            "before update or delete",
            "before truncate",
            "remote_attempts",
            "retention",
        ),
        "operator controls",
    )
    require(
        boundary_test,
        ("GAME_SERVER_SOURCE", "SETTLEMENT_WORKER_RUNTIME_SOURCE", "OUT_DIR"),
        "direct ownership test",
    )
    require(capture_test, ("capture", "claim", "remote"), "capture commit test")
    require(
        operator_test,
        ("settlement_operator_replay_is_exact_audited_one_attempt_and_append_only", "remote_attempts"),
        "operator PostgreSQL test",
    )
    require(
        workflow,
        (
            "settlement_game_server_boundary",
            "settlement_operator_controls_database",
            "cargo fmt --all -- --check",
            "cargo clippy -p trnm-game-server --all-targets --locked -- -D warnings",
        ),
        "settlement workflow",
    )

print(
    "TRNM settlement transaction boundary: PASS "
    "(direct entrypoints, capture/execute/apply, durable identity, live lease, "
    "operator replay and append-only evidence are fail-closed)"
)
PY
'''

boundary_test_path = crate / "tests/settlement_game_server_boundary.rs"
boundary_script_path = root / "scripts/check-trnm-settlement-transaction-boundary.sh"
for path in (boundary_test_path, boundary_script_path):
    if not path.is_file():
        raise SystemExit(f"missing source to materialize: {path}")

boundary_test_path.write_text(boundary_test, encoding="utf-8")
boundary_script_path.write_text(boundary_script, encoding="utf-8")
boundary_script_path.chmod(0o755)
