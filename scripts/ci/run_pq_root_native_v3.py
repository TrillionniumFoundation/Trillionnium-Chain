#!/usr/bin/env python3
"""Execute exact V3 Rust component selectors and refuse empty/skipped results.

This retains failed commands and full raw logs. It never executes production
root changes or promotes whole-chain, deployment or lifetime qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

from verify_ci_source import verify

ROOT = Path(__file__).resolve().parents[2]
CRYPTO_STRUCTURE = (
    "exact_spki_lengths_and_suite_identity_are_bound",
    "same_length_shake_oid_and_weaker_mldsa_cannot_be_mislabeled",
    "entire_roster_is_exact_distinct_and_immutable_including_unused_keys",
    "canonical_codec_roundtrips_and_rejects_all_truncations_and_trailing_bytes",
    "decoder_refuses_noncanonical_order_or_altered_policy_or_lengths",
    "complete_statement_is_framed_and_maximum_payload_is_supported",
    "operation_identity_contains_intent_but_no_selected_quorum_or_signature_bytes",
    "successor_possession_binds_full_roster_role_and_full_intent",
    "failed_reservations_remain_charged_and_never_wrap_or_reset",
    "shared_budget_has_one_absolute_deadline_and_irreversible_cancellation",
)
CRYPTO_NATIVE = (
    "exact_oid_native_generation_and_cross_backend_ml87_verification_work",
    "all_nine_quorum_pairs_verify_one_operation_identity",
    "complete_maximum_statement_and_all_six_successor_possessions_verify",
    "each_family_corruption_and_one_family_only_fail_without_or_fallback",
    "complete_intent_and_domain_mutations_invalidate_real_current_signatures",
    "every_successor_proof_is_mandatory_and_cannot_move_between_roles_or_intents",
    "genuine_shake_key_is_rejected_despite_identical_key_and_signature_sizes",
    "malformed_and_cancelled_attempts_use_the_original_budget_before_crypto",
    "warm_roster_preserves_full_quorum_and_budget_accounting",
)
CRYPTO_CACHED = (
    "native_cache_v3_lazy_shared_and_identity_neutral",
    "native_cache_v3_rechecks_exact_message_and_signature",
    "native_cache_v3_waits_for_shape_and_original_budget",
)
KERNEL = (
    "native_v3_all_five_actions_require_real_fixed_dual_quorum",
    "native_v3_successor_requires_every_separate_possession",
    "native_v3_shared_budget_does_not_reset_between_old_and_successor",
    "native_v3_nine_quorum_choices_share_semantic_operation",
    "native_v3_nonce_and_revocations_survive_generation_change",
    "native_v3_current_intent_rechecks_rotation_revocation_and_expiry",
    "native_v3_expired_recovery_keeps_both_current_quorums",
    "native_v3_full_intent_scope_epoch_predecessor_and_time_are_bound",
    "native_v3_canonical_wire_rejects_aliases_truncation_and_unknown_action",
    "native_v3_capacity_never_prunes_nonce_history",
    "native_v3_time_is_exclusive_unix_and_artifact_observations_are_exact",
    "native_v3_bounded_intent_rejects_unbounded_material_before_hashing",
)
# Exact reviewed public integration tests; no ignored or inferred results.
OWNER = (
    "native_owner_v3_domain_binds_each_independent_identity_without_zero_fallback",
    "native_owner_v3_real_signed_append_reopen_and_exact_intent_observation",
    "native_owner_v3_replay_preserves_nonce_and_refuses_second_exact_operation",
    "native_owner_v3_lost_successful_cas_reply_requires_explicit_exact_completion",
    "native_owner_v3_unadvanced_anchor_cannot_clear_pending_or_retry",
    "native_owner_v3_corrupt_pending_state_cannot_promote_even_after_real_cas",
    "native_owner_v3_retained_external_anchor_refuses_whole_local_rollback",
    "native_owner_v3_co_restored_owner_and_anchor_counterexample_remains_accepted",
    "native_owner_v3_wrong_enrollment_scope_and_service_aliases_are_refused",
    "native_owner_v3_successor_cannot_reuse_an_anchor_or_writer_key",
    "native_owner_v3_last_observation_rechecks_persisted_revocation_and_rotation",
    "native_owner_v3_authenticated_response_still_must_bind_fresh_challenge",
    "native_owner_v3_writer_signature_is_verified_before_transport",
    "native_owner_v3_callback_cannot_replace_original_owner_budget",
    "native_owner_v3_same_budget_exhaustion_retains_pending_before_cas",
    "native_owner_v3_cancellation_after_external_commit_requires_reconciliation",
    "native_owner_v3_storage_tamper_schema_alias_and_concurrent_open_fail_closed",
    "native_owner_v3_changed_current_bytes_and_replaced_database_are_not_authority",
    "native_owner_v3_foreign_sqlite_namespace_is_refused_without_mutating_it",
    "native_owner_v3_reopen_reverifies_retained_signature_bytes",
)


def checked_result(raw: str, expected: tuple[str, ...], returncode: int) -> dict:
    if returncode != 0 or not expected or len(set(expected)) != len(expected):
        raise ValueError("failed command or invalid required-test inventory")
    summaries = re.findall(
        r"^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
        r"(\d+) measured; (\d+) filtered out; finished in .+$", raw, re.M)
    if len(summaries) != 1:
        raise ValueError("one actual Rust test summary required")
    status, passed, failed, ignored, measured, filtered = summaries[0]
    if (status, int(passed), int(failed), int(ignored), int(measured)) != (
            "ok", len(expected), 0, 0, 0):
        raise ValueError("required Rust tests missing, failed, measured or ignored")
    observed = re.findall(r"^test ([A-Za-z0-9_:]+) \.\.\. (.+)$", raw, re.M)
    if len(observed) != len(expected) or any(outcome != "ok" for _, outcome in observed):
        raise ValueError("all named tests must actually finish successfully")
    names = [name for name, _ in observed]
    if len(set(names)) != len(names) or set(names) != set(expected):
        raise ValueError("different or duplicate native tests")
    if re.findall(r"^running (\d+) tests?$", raw, re.M) != [str(len(expected))]:
        raise ValueError("empty, duplicate or wrong discovery")
    return {"tests": sorted(names), "passed": len(names), "filtered_out": int(filtered)}


def suites():
    base = ["cargo", "test", "--locked", "--manifest-path", "trillionnium/Cargo.toml"]
    suffix = ["--", "--nocapture", "--test-threads=1"]
    return (
        ("crypto-structure", base + ["-p", "trnm-crypto-primitives", "--lib", "pq_root_v3::tests::"] + suffix,
         tuple("pq_root_v3::tests::" + x for x in CRYPTO_STRUCTURE)),
        ("crypto-native", base + ["-p", "trnm-crypto-primitives", "--features", "pq-native-openssl",
                                 "--test", "pq_root_v3_native"] + suffix, CRYPTO_NATIVE),
        ("crypto-cached-keys", base + ["-p", "trnm-crypto-primitives", "--features", "pq-native-openssl",
                                      "--lib", "pq_root_v3::tests::native_cache_v3_"] + suffix,
         tuple("pq_root_v3::tests::" + x for x in CRYPTO_CACHED)),
        ("root-kernel", base + ["-p", "trnm-release-bundle", "--features", "pq-root-v3",
                               "--lib", "root_recovery_v3::tests::"] + suffix,
         tuple("root_recovery_v3::tests::" + x for x in KERNEL)),
        ("root-owner", base + ["-p", "trnm-pon-node", "--features", "pq-root-v3",
                              "--test", "root_recovery_v3_native"] + suffix, OWNER),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if len(OWNER) != 20:
        raise ValueError("complete reviewed native owner test list required")
    output = args.out or Path(os.environ.get("TRNM_CI_RECEIPT_DIR", "/tmp/trnm-root-v3")) / "root-native-v3"
    output.mkdir(parents=True, exist_ok=False)
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    before = verify("head", head, root=ROOT)
    (output / "source-before.json").write_text(json.dumps(before, indent=2) + "\n")
    records = []
    for name, argv, expected in suites():
        log = output / (name + ".log")
        start = time.monotonic()
        try:
            with log.open("xb") as stream:
                result = subprocess.run(argv, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT, timeout=1200)
            code = result.returncode
        except subprocess.TimeoutExpired:
            code = 124
        except OSError as exception:
            code = 127
            with log.open("ab") as stream:
                stream.write((str(exception) + "\n").encode("utf-8"))
        raw = log.read_bytes()
        error = None
        observation = None
        try:
            observation = checked_result(raw.decode("utf-8", errors="strict"), expected, code)
        except (ValueError, UnicodeError) as exception:
            error = str(exception)
        record = {"name": name, "argv": argv, "source": head, "exit_code": code,
                  "elapsed_seconds": time.monotonic() - start,
                  "log": log.name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                  "observation": observation, "error": error}
        records.append(record)
        (output / "commands.json").write_text(json.dumps(records, indent=2) + "\n")
        print(json.dumps(record), flush=True)
    after = verify("head", head, root=ROOT)
    (output / "source-after.json").write_text(json.dumps(after, indent=2) + "\n")
    passed = before == after and all(row["error"] is None for row in records)
    report = {"schema": "trnm-pq-root-native-components-v3", "source": head,
              "component_execution_passed": passed, "commands": records,
              "status": "HOLD", "production_activation": False,
              "actual_lifetime_failure_bound": None, "whole_chain_pq_qualified": False,
              "composition_coverage_proved": False}
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
