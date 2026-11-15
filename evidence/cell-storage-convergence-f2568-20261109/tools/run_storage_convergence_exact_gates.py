#!/usr/bin/env python3
"""Run the retained nineteen plus six convergence gates on exact source.

Read one JSON object from stdin. Required keys: root, out, target,
provider_path, native_tmp, sha, tree, native_expectations. Optional keys: provider_receipt_path,
rustup (default the user's .cargo/bin/rustup), synthetic_tmp_root (/dev/shm).
All task paths except synthetic scratch
must be under the current user's existing work directory. out must be new;
native_tmp must be new or empty. This runner never fetches, installs, or retries.

The provider_path input is validated-provider.json from the isolated preparation;
its default underlying receipt is observations/pq-provider/provider.json beside
that file. Native/Cargo commands always use the verified persistent native_tmp.
Only the three named synthetic Python controls use an isolated tmpfs directory.
Their PATH blocks Rust tool execution and records attempted calls; this is an
additional guard for the audited scripts, not an operating-system sandbox.

native_expectations freezes every complete DA and filtered Node harness count
and full selected test roster for the final commit. Required new controls are
also checked by exact fully qualified names; TCA3 already includes its three
residency controls. This runner never substitutes compile-only or past-source
results for execution and never rewrites the source checkout.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import traceback


TOOLCHAIN = "1.95.0"
OPENSSL_VERSION = "3.5.9"
OPENSSL_ARCHIVE_SHA256 = "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a"
PROVIDER_EXPORTS = {
    "OPENSSL_DIR", "OPENSSL_STATIC", "TRNM_PQ_OPENSSL",
    "TRNM_PQ_OPENSSL_SHA256", "TRNM_PQ_OPENSSL_VERSION",
    "OPENSSL_CONF", "OPENSSL_MODULES",
}
PROVIDER_INPUTS = (
    "bin/openssl", "include/openssl/opensslv.h",
    "include/openssl/configuration.h", "lib/libcrypto.a", "lib/libssl.a",
)
SYNTHETIC = {"source-negative-controls", "pq-negative-controls", "ci-contract-controls"}
BLOCKED_TOOLS = ("cargo", "rustc", "rustdoc", "rustup", "cargo-clippy", "cargo-fmt")
LOCAL_FILESYSTEMS = {"ext4", "xfs", "btrfs", "f2fs"}
PROCESS_DEATH_PARENT = "cell::retention::tests::real_process_death_after_payload_sync_recovers_ack_without_origin_or_new_capacity"
PROCESS_DEATH_CHILD = "cell::retention::tests::retention_process_child"
# The two exact Linux stdout forms observed in this retained test. Its child
# exits with 91 before its own libtest result. The parent's final `ok` can
# follow the child's printed test prefix; it completes only the parent here.
# The child's separate ordinary harness case still counts in the full roster.
PROCESS_DEATH_LINES = ("test " + PROCESS_DEATH_PARENT + " ... ", "running 1 test", "ok")
PROCESS_DEATH_CHILD_PREFIX_LINES = (
    PROCESS_DEATH_LINES[0], PROCESS_DEATH_LINES[1], "test " + PROCESS_DEATH_CHILD + " ... ok")
PROCESS_DEATH_FORMS = (PROCESS_DEATH_LINES, PROCESS_DEATH_CHILD_PREFIX_LINES)

# Minimum new controls. Counts for the complete runtime are supplied by the
# final immutable configuration; no old whole-crate count is embedded here.
REQUIRED_NEW_TESTS = {
    "complete-da-native": {
        "discovery": [
            "cell::discovery::pq::auth::tests::authenticated_v3_real_server_active_provider_precedes_eight_withdrawals",
            "cell::discovery::pq::auth::tests::authenticated_v3_real_server_expired_authority_preserves_verification_slots",
            "cell::discovery::pq::auth::tests::authenticated_v3_real_server_revoked_authority_preserves_verification_slots",
            "cell::discovery::pq::auth::tests::authenticated_v3_observed_partial_reply_retains_original_shared_denominator",
            "cell::discovery::pq::auth::tests::authenticated_v3_observed_failed_manifest_includes_payload_session_costs_once",
            "cell::discovery::pq::auth::tests::authenticated_v3_observed_announcement_refusal_preserves_signature_units",
            "cell::discovery::pq::auth::tests::authenticated_v3_announcement_original_monotonic_lease_cannot_be_renewed_by_wall_time",
            "cell::discovery::pq::auth::tests::authenticated_v3_parallel_profile_magic_never_enables_wire_or_domain_fallback",
            "cell::discovery::pq::auth::tests::authenticated_v3_parallel_database_profile_is_refused_without_reinterpretation"
        ],
        "host_handoff": [
            "cell::host_handoff::tests::host_handoff_chb1_keeps_both_contexts_and_rejects_old_wire_aliases",
            "cell::host_handoff::tests::host_handoff_cpv4_and_both_real_sealed_scopes_are_required_for_exact_fd_data"
        ],
        "retained_shard_plan": [
            "cell::version_retention::tests::shard_plan::retained_shard_plan_reopens_all_versions_six_actual_slots_and_four_slot_full_recovery",
            "cell::version_retention::tests::shard_plan::retained_shard_plan_pending_expired_or_added_catalog_roots_cannot_be_omitted",
            "cell::version_retention::tests::shard_plan::retained_shard_plan_requires_full_distinct_funding_roster_before_file_creation",
            "cell::version_retention::tests::shard_plan::retained_shard_plan_self_consistent_subset_still_fails_actual_owner_coverage",
            "cell::version_retention::tests::shard_plan::retained_shard_plan_namespace_pins_and_actual_immutable_file_are_checked"
        ],
        "shard_provider": [
            "cell::erasure::provider::tests::csp1_roundtrip_keeps_independent_source_operation_context_and_slot_pins",
            "cell::erasure::provider::tests::provider_reopens_full_descriptor_and_reads_actual_bytes_without_cache",
            "cell::erasure::provider::tests::provider_lost_publish_result_reconciles_without_source_or_second_charge",
            "cell::erasure::provider::tests::provider_initial_unknown_never_redispatches_after_source_returns",
            "cell::erasure::provider::tests::provider_unknown_repair_keeps_debit_across_reopen_and_budget_exhaustion",
            "cell::erasure::provider::tests::provider_reconstructs_from_actual_four_arenas_and_repairs_actual_fifth_slot",
            "cell::erasure::provider::tests::provider_metadata_limit_rejects_before_creating_new_file_and_keeps_terminal_history",
            "cell::erasure::provider::tests::provider_descriptor_fault_or_wrong_owner_never_returns_existing_arena_success",
            "cell::erasure::provider::tests::provider_expired_deadline_and_immediate_cancel_create_no_slot",
            "cell::retention::payload_read::tests::bounded_arena_read_returns_exact_multichunk_bytes_without_cache_or_debit_changes",
            "cell::retention::payload_read::tests::bounded_arena_read_refuses_pending_retired_and_missing_obligations",
            "cell::retention::payload_read::tests::bounded_arena_read_enforces_allocation_and_original_deadline_without_recharging",
            "cell::retention::payload_read::tests::bounded_arena_read_checks_actual_late_chunk_and_cannot_substitute_cache_bytes",
            "cell::retention::payload_read::tests::bounded_arena_read_cancellation_is_not_swallowed_as_corruption_or_repair_permission",
            "cell::retention::payload_read::tests::bounded_arena_read_refuses_replaced_path_even_when_old_fd_has_valid_bytes"
        ],
        "snapshot": [
            "cell::snapshot_schedule::tests::periodic_policy_matches_independent_python_wire_commitment_and_due_heights",
            "cell::snapshot_schedule::tests::periodic_snapshot_policy_codec_has_exact_namespace_and_finite_cadence",
            "cell::snapshot_schedule::tests::periodic_snapshot_actual_dual_closure_copy_reopens_target_only_and_keeps_retired_cursor",
            "cell::snapshot_schedule::tests::periodic_snapshot_partial_environment_and_missing_cache_keep_same_pending_identity",
            "cell::snapshot_schedule::tests::periodic_snapshot_disk_policy_tampering_and_wrong_pin_prevent_catalog_mutation",
            "cell::snapshot_schedule::tests::periodic_snapshot_policy_symlink_directory_link_and_hardlink_are_refused",
            "cell::snapshot_schedule::tests::periodic_snapshot_changed_ordinal_due_predecessor_schedule_and_scope_are_refused",
            "cell::snapshot_schedule::tests::periodic_snapshot_direct_history_short_lease_cannot_become_recovery_cursor",
            "cell::snapshot_schedule::tests::periodic_snapshot_direct_history_changed_due_is_not_trusted_as_a_cursor",
            "cell::snapshot_schedule::tests::periodic_snapshot_late_tick_preserves_original_due_and_expiry",
            "cell::snapshot_schedule::tests::periodic_snapshot_initial_anchor_store_owner_and_coverage_are_independent_pins",
            "cell::snapshot_schedule::tests::periodic_snapshot_original_deadline_prevents_creation_or_catalog_work"
        ],
        "version_retention": [
            "cell::version_retention::tests::complete_owner_codec_binds_both_independent_generations_and_all_original_terms",
            "cell::version_retention::tests::complete_owner_matches_independent_python_wire_and_real_three_transition_anchors",
            "cell::version_retention::tests::complete_owner_model_only_copy_restarts_pending_and_keeps_environment_protected",
            "cell::version_retention::tests::complete_owner_lost_catalog_ack_reconciles_actual_targets_after_cache_deletion",
            "cell::version_retention::tests::complete_owner_prior_pending_unallocated_union_cannot_double_promise_capacity",
            "cell::version_retention::tests::complete_owner_anchor_accepts_committed_unknown_prefix_and_rejects_old_catalog_restore",
            "cell::version_retention::tests::complete_owner_stale_generation_and_changed_original_contract_do_not_mutate_catalog",
            "cell::version_retention::tests::complete_owner_shared_objects_survive_first_retirement_and_expired_unretired_reference",
            "cell::version_retention::tests::complete_owner_retired_root_live_slots_stay_charged_until_physical_gc",
            "cell::version_retention::tests::complete_owner_retired_identity_history_never_reclaims_record_capacity",
            "cell::version_retention::tests::complete_owner_unknown_repair_with_fsynced_healthy_target_blocks_gc_until_reconcile",
            "cell::version_retention::tests::complete_owner_failed_original_copy_is_not_redispatched_with_a_good_cache",
            "cell::version_retention::tests::complete_owner_service_view_cannot_hide_pending_or_expired_members_of_r",
            "cell::version_retention::tests::complete_owner_expired_corrupt_acknowledged_payload_can_retire_without_refund",
            "cell::version_retention::tests::complete_owner_snapshot_link_requires_real_completed_predecessor_and_unique_cursor",
            "cell::version_retention::tests::complete_owner_namespace_or_event_corruption_never_opens_as_empty_history",
            "cell::version_retention::tests::complete_owner_metadata_cap_refuses_before_new_pending_identity",
            "cell::version_retention::tests::complete_owner_all_pending_versions_count_toward_protected_cap_even_after_expiry",
            "cell::version_retention::tests::complete_owner_deadline_and_cancellation_never_create_an_admitted_empty_subset",
            "cell::version_retention::tests::residency::retained_complete_targets_cold_rehydrate_both_components_then_feed_two_real_resident_callbacks",
            "cell::version_retention::tests::residency::retained_environment_damage_cannot_be_recovered_from_complete_metadata_or_a_good_model",
            "cell::version_retention::tests::residency::retained_joint_task_enforces_full_ram_both_current_contexts_and_latched_cancel_before_callback"
        ],
        "research_fds": [
            "cell::host_handoff::tests::research_fds::research_fd_sender_transfers_actual_complete_sealed_pair_with_original_deadline",
            "cell::host_handoff::tests::research_fds::research_fd_sender_refuses_changed_pins_budget_task_parent_or_expiry_before_any_byte"
        ],
        "retained_shard_capacity": [
            "cell::version_retention::tests::shard_plan::capacity::retained_shard_plan_initial_128_profile_accepts_complete_65_and_128_chunk_catalogs",
            "cell::version_retention::tests::shard_plan::capacity::retained_shard_plan_initial_128_profile_refuses_129_complete_chunks_before_staging",
            "cell::version_retention::tests::shard_plan::capacity::retained_shard_plan_initial_128_profile_keeps_original_two_mib_wire_and_file_ceiling"
        ]
    },
    "node-storage-owner-native": {
        "retained_shard_plan": [
            "store::storage_service::tests::version::shard_plan::native_complete_version_to_complete_local_shard_plan_reopens_without_sources_or_new_debits"
        ],
        "shard": [
            "store::storage_service::tests::shard::native_shard_real_funding_target_readback_and_repair_keep_original_debits",
            "store::storage_service::tests::shard::native_shard_pending_initial_effect_cannot_dispatch_even_with_source_present",
            "store::storage_service::tests::shard::native_shard_unknown_repair_never_reissues_and_foreign_owner_cannot_retire"
        ],
        "version": [
            "store::storage_service::tests::version::native_version_reorg_keeps_custody_but_cannot_grant_new_funding_or_foreign_retirement",
            "store::storage_service::tests::version::native_version_scheduler_pending_metadata_accepts_only_new_funded_copy_then_reopens_done",
            "store::storage_service::tests::version::native_version_pending_monetary_effect_cannot_retry_copy_with_a_new_source",
            "store::storage_service::tests::version::native_version_scope_alias_and_late_funding_errors_precede_every_reservation",
            "store::storage_service::tests::version::native_version_outer_history_cannot_invent_missing_member_intents"
        ],
        "recovery": [
            "store::storage_service::tests::version::shard_plan::recovery::native_shard_plan_automatic_recovery_uses_four_targets_after_all_sources_are_deleted",
            "store::storage_service::tests::version::shard_plan::recovery::native_shard_plan_recovery_refuses_missing_quorum_without_spending_new_repairs_or_refunding_reads",
            "store::storage_service::tests::version::shard_plan::recovery::native_shard_plan_pending_repair_cannot_redispatch_and_needs_independent_new_funding",
            "store::storage_service::tests::version::shard_plan::recovery::native_shard_plan_recovery_preflight_cpu_and_metadata_fail_closed_without_hidden_copies"
        ]
    }
}

SEALED_PYTHON_REQUIRED_NAMES = [
    "test_actual_scm_rights_keeps_seals_bytes_and_original_deadline",
    "test_both_sha256_and_stronger_payload_domain_are_checked",
    "test_complete_pair_reads_same_sealed_bytes_without_any_model_path",
    "test_complete_snapshot_ram_and_original_generation_refuse_before_read",
    "test_descriptor_bootstrap_and_owner_pin_cannot_be_replaced",
    "test_expiry_is_checked_before_input_use_and_is_not_reset",
    "test_explicit_material_bridge_uses_sealed_original_pair_and_complete_loaded_contract",
    "test_failed_supervisor_cancels_connector_before_handshake",
    "test_failed_supervisor_cancels_ready_wait_after_sealed_handoff",
    "test_fixed_bootstrap_executes_actual_independently_pinned_sealed_worker_bytes",
    "test_fixed_bootstrap_refuses_substituted_worker_before_any_entry",
    "test_fixed_bootstrap_refuses_unsealed_worker_before_any_entry",
    "test_independent_environment_pin_cannot_follow_supplied_new_bytes",
    "test_kernel_write_seals_and_cloexec_are_required",
    "test_missing_scope_or_swapped_role_refuses_the_complete_admission",
    "test_observation_publish_is_complete_before_visibility_and_cannot_replace",
    "test_original_modules_and_configurations_execute_only_same_admitted_fd_bytes",
    "test_project_source_compiler_preserves_original_annotation_semantics",
    "test_runtime_module_origin_refuses_other_relative_paths",
    "test_runtime_virtual_namespace_refuses_source_or_loader_drift",
    "test_runtime_virtual_namespace_requires_exact_pinned_singleton",
    "test_same_length_substituted_fd_fails_actual_content_digest",
    "test_unfinished_publication_remains_pending_without_successful_ready",
    "test_unknown_file_and_metadata_role_never_open_ambient_payload"
]


class GateError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def json_load(data: bytes) -> dict:
    result = json.loads(data, object_pairs_hook=unique_object)
    require(isinstance(result, dict), "expected a JSON object")
    return result


def file_identity(path: Path) -> dict:
    before = path.stat(follow_symlinks=False)
    require(stat.S_ISREG(before.st_mode), "input is not a regular file: " + str(path))
    fingerprint = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                                info.st_mtime_ns, info.st_ctime_ns)
    value = hashlib.sha256()
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        require(fingerprint(os.fstat(stream.fileno())) == fingerprint(before),
                "input changed before hashing: " + str(path))
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
        require(fingerprint(os.fstat(stream.fileno())) == fingerprint(before),
                "input changed during hashing: " + str(path))
    require(fingerprint(path.stat(follow_symlinks=False)) == fingerprint(before),
            "input path changed during hashing: " + str(path))
    return {"path": str(path), "bytes": before.st_size, "sha256": value.hexdigest()}


def read_json_file(path: Path) -> tuple[dict, dict]:
    require(path.stat().st_size <= 1024 * 1024, "JSON receipt exceeds 1 MiB")
    data = path.read_bytes()
    identity = file_identity(path)
    require(hashlib.sha256(data).hexdigest() == identity["sha256"], "JSON input changed")
    return json_load(data), identity


def scrub_environment(inherited: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    """Remove ambient profile, compiler, runner, Git and provider overrides.

    HOME is never changed. Cargo/Rustup homes remain inputs so installed tools
    and the already populated offline cache can be used; their configs are
    checked separately. Record only removed names, never credentials/values.
    """
    environment = inherited.copy()
    removed = []
    for key in list(environment):
        if ((key.startswith("CARGO_") and key != "CARGO_HOME")
                or (key.startswith("RUST") and key != "RUSTUP_HOME")
                or key.startswith("GIT_") or "OPENSSL" in key
                or key in {"LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"}):
            removed.append(key)
            del environment[key]
    return environment, sorted(removed)


def cargo_config_inputs(root: Path, cargo_home: Path) -> list[dict]:
    """Hash only Cargo's discovery locations; reject execution/profile changes.

    Registry/cache configuration may remain. Never read credentials.toml or
    print configuration values. The current directory is the source root for
    every Cargo command, including those with an explicit --manifest-path.
    """
    directories = [cargo_home, *(parent / ".cargo" for parent in (root, *root.parents))]
    paths = sorted({directory / name for directory in directories for name in ("config", "config.toml")
                    if (directory / name).exists()}, key=str)
    identities = []
    for path in paths:
        raw = path.read_bytes()
        identity = file_identity(path)
        require(hashlib.sha256(raw).hexdigest() == identity["sha256"], "Cargo config changed during read")
        data = tomllib.loads(raw.decode("utf-8"))
        forbidden = []
        for key in ("profile", "unstable", "paths", "patch", "replace"):
            if data.get(key):
                forbidden.append(key)
        build = data.get("build", {})
        for key in ("rustc", "rustc-wrapper", "rustc-workspace-wrapper", "rustdoc", "rustflags",
                    "rustdocflags", "target"):
            if key in build:
                forbidden.append("build." + key)
        for target, settings in data.get("target", {}).items():
            if not isinstance(settings, dict):
                continue
            for key in ("runner", "linker", "rustflags", "rustdocflags"):
                if key in settings:
                    forbidden.append("target." + target + "." + key)
            for key, value in settings.items():
                if isinstance(value, dict):
                    forbidden.append("target." + target + "." + key + " (build-script override)")
        for key in data.get("env", {}):
            if (key.startswith(("CARGO_", "RUST", "GIT_")) or "OPENSSL" in key
                    or key in {"PATH", "TMPDIR", "TMP", "TEMP", "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"}):
                forbidden.append("env." + key)
        for key in ("metadata", "fmt", "test", "clippy"):
            if key in data.get("alias", {}):
                forbidden.append("alias." + key)
        require(not forbidden, "Cargo configuration changes native execution: " + str(path) + " keys=" + ",".join(forbidden))
        identities.append(identity)
    return identities


def native_results(lines: list[str]) -> dict:
    pattern = re.compile(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in .+$")
    rows = []
    for line in lines:
        match = pattern.fullmatch(line)
        require(match is not None, "unrecognized native test result line")
        values = [int(value) for value in match.groups()[1:]]
        require(match.group(1) == "ok" and values[1:] == [0, 0, 0, 0],
                "native tests failed, were ignored/measured, or were filtered")
        rows.append(dict(zip(("passed", "failed", "ignored", "measured", "filtered_out"), values)))
    require(rows and sum(row["passed"] for row in rows) > 0,
            "native exit success lacks positive, unfiltered test execution")
    return {"harnesses": rows, "total_passed": sum(row["passed"] for row in rows)}


def validate_native_expectations(value: object) -> dict:
    """Freeze complete harness counts and names without accepting an empty gate.

    Names belong to their actual harness. Duplicate ordinary names in different
    binaries may be legitimate; each new fully qualified control must occur
    exactly once across the command's harnesses.
    """
    require(isinstance(value, dict) and set(value) == set(REQUIRED_NEW_TESTS),
            "native_expectations must describe exactly the two native gates")
    for label, entry in value.items():
        require(isinstance(entry, dict)
                and set(entry) == {"total_passed", "harnesses", "new_test_roster"},
                "invalid frozen native expectation: " + label)
        harnesses = entry["harnesses"]
        require(isinstance(harnesses, list) and 1 <= len(harnesses) <= 128,
                "expected native harness list is empty or oversized: " + label)
        if label == "node-storage-owner-native":
            require(len(harnesses) == 1, "Node --lib module gate must describe one harness")
        all_names = []
        for harness in harnesses:
            require(isinstance(harness, dict)
                    and set(harness) == {"passed", "filtered_out", "test_names"},
                    "invalid frozen harness fields: " + label)
            for field in ("passed", "filtered_out"):
                require(type(harness[field]) is int and 0 <= harness[field] <= 1_000_000,
                        "invalid frozen harness count: " + label + "/" + field)
            names = harness["test_names"]
            require(isinstance(names, list) and len(names) == harness["passed"]
                    and all(isinstance(name, str) and 0 < len(name) <= 4096
                            and "\n" not in name and "\r" not in name for name in names),
                    "complete harness roster length differs from passed count: " + label)
            require(len(set(names)) == len(names), "duplicate test in a frozen harness: " + label)
            if label == "complete-da-native":
                require(harness["filtered_out"] == 0, "complete DA gate cannot expect a filtered harness")
            all_names.extend(names)
        total = sum(harness["passed"] for harness in harnesses)
        require(type(entry["total_passed"]) is int and entry["total_passed"] == total and total > 0,
                "frozen native total is zero or differs from its complete harness counts: " + label)
        roster = entry["new_test_roster"]
        require(isinstance(roster, dict) and set(REQUIRED_NEW_TESTS[label]) <= set(roster),
                "frozen new-test roster omits a required group: " + label)
        new_names = []
        for group, names in roster.items():
            require(isinstance(group, str) and re.fullmatch(r"[a-z][a-z0-9_]*", group) is not None,
                    "invalid native roster group")
            require(isinstance(names, list) and names
                    and all(isinstance(name, str)
                            and re.fullmatch(r"(?:[A-Za-z_][A-Za-z0-9_]*::)+[A-Za-z_][A-Za-z0-9_]*", name)
                            for name in names), "new roster requires exact fully qualified Rust names")
            required = set(REQUIRED_NEW_TESTS[label].get(group, []))
            require(required <= set(names), "frozen roster omits required new tests: " + label + "/" + group)
            prefix = "cell::" if label == "complete-da-native" else "store::storage_service::"
            require(all(name.startswith(prefix) for name in names), "new test is outside its native gate scope")
            new_names.extend(names)
        require(len(new_names) == len(set(new_names)),
                "new-test roster double counts a case, including TCA3 residency: " + label)
        require(all(all_names.count(name) == 1 for name in new_names),
                "new control is absent or duplicated in the complete frozen native roster: " + label)
    return value


def exact_native_execution(stdout: str, expected: dict, label: str) -> dict:
    """Require actual successful runtime output, complete counts and exact cases."""
    running_pattern = re.compile(r"^running (\d+) tests?$")
    case_pattern = re.compile(r"^test (.+) \.\.\. (ok|FAILED|ignored(?:, .*)?)$")
    result_pattern = re.compile(
        r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
        r"(\d+) measured; (\d+) filtered out; finished in .+$")
    harnesses = []
    active = None
    lines = stdout.splitlines()
    skip_until = 0
    nested = []
    for index, line in enumerate(lines):
        if index < skip_until:
            continue
        if line == PROCESS_DEATH_LINES[0]:
            require(label == "complete-da-native" and active is not None and not nested
                    and len(harnesses) < len(expected["harnesses"])
                    and PROCESS_DEATH_PARENT in expected["harnesses"][len(harnesses)]["test_names"],
                    "unexpected or repeated retained process-death parent")
            observed_lines = tuple(lines[index:index + 3])
            require(observed_lines in PROCESS_DEATH_FORMS,
                    "retained process-death observation differs from its two exact three-line forms")
            active["tests"].append({"name": PROCESS_DEATH_PARENT, "status": "ok"})
            nested.append({"parent_test": PROCESS_DEATH_PARENT, "start_line": index + 1,
                           "observed_lines": list(observed_lines),
                           "child_independent_results_counted": 0, "parent_results_counted": 1})
            skip_until = index + 3
            continue
        require(line != "ok", "standalone ok is allowed only in the exact retained process-death observation")
        running = running_pattern.fullmatch(line)
        require(not line.startswith("running ") or running is not None,
                "unrecognized native running banner")
        if running is not None:
            require(active is None, "native harness started before the preceding result")
            active = {"declared_tests": int(running.group(1)), "tests": []}
            continue
        if line.startswith("test result:"):
            match = result_pattern.fullmatch(line)
            require(active is not None and match is not None, "native result lacks its running harness")
            passed, failed, ignored, measured, filtered = map(int, match.groups()[1:])
            require(match.group(1) == "ok" and failed == ignored == measured == 0,
                    "native harness failed or ignored/measured tests")
            names = [row["name"] for row in active["tests"]]
            require(active["declared_tests"] == passed == len(names)
                    and len(set(names)) == len(names)
                    and all(row["status"] == "ok" for row in active["tests"]),
                    "native declared count, completed names or statuses disagree")
            harnesses.append({"passed": passed, "filtered_out": filtered, "test_names": names})
            active = None
            continue
        if line.startswith("test "):
            match = case_pattern.fullmatch(line)
            require(active is not None and match is not None, "unrecognized or out-of-harness native test line")
            active["tests"].append({"name": match.group(1), "status": match.group(2)})
    require(active is None and harnesses, "native execution lacks complete harness results")
    require(len(harnesses) == len(expected["harnesses"]), "actual native harness count differs from frozen expectation")
    for index, (actual, planned) in enumerate(zip(harnesses, expected["harnesses"])):
        require(actual["passed"] == planned["passed"]
                and actual["filtered_out"] == planned["filtered_out"]
                and set(actual["test_names"]) == set(planned["test_names"]),
                "actual complete native count/roster differs at harness " + str(index) + " of " + label)
    total = sum(harness["passed"] for harness in harnesses)
    require(total == expected["total_passed"] and total > 0, "actual native total differs or is zero")
    actual_names = [name for harness in harnesses for name in harness["test_names"]]
    groups = {}
    for group, names in expected["new_test_roster"].items():
        require(all(actual_names.count(name) == 1 for name in names),
                "required new control was not executed exactly once: " + group)
        groups[group] = {"passed": len(names), "names": names}
    return {"harnesses": harnesses, "total_passed": total, "new_test_execution": groups,
            "nested_child_observations": nested,
            "frozen_expectation_sha256": hashlib.sha256(json.dumps(expected, sort_keys=True).encode()).hexdigest(),
            "scope": ("complete default-feature DA crate including its actual lib/bin/doc harnesses"
                      if label == "complete-da-native"
                      else "filtered storage_service library module; not the complete Node crate")}


def exact_sealed_python_execution(output: str) -> dict:
    """Require the genuine verbose unittest transcript for all fixed controls."""
    case = re.compile(
        r"^(test_[a-z0-9_]+) \(test_llm_cell_sealed_worker_v1"
        r"\.SealedHandoffControls\.(test_[a-z0-9_]+)\) \.\.\. ok$"
    )
    summary = re.compile(r"^Ran (\d+) tests in \d+(?:\.\d+)?s$")
    names = []
    reported = []
    successes = 0
    state = "cases"
    for line in output.splitlines():
        if not line:
            continue
        match = case.fullmatch(line)
        if match:
            require(
                state == "cases" and match.group(1) == match.group(2),
                "sealed Python case identity or order changed",
            )
            names.append(match.group(1))
            continue
        if line == "-" * 70:
            require(state == "cases" and bool(names), "unexpected Python harness boundary")
            state = "summary"
            continue
        match = summary.fullmatch(line)
        if match:
            require(state == "summary" and not reported, "unexpected Python summary")
            reported.append(int(match.group(1)))
            state = "result"
            continue
        if line == "OK":
            require(state == "result", "unexpected Python success marker")
            successes += 1
            state = "complete"
            continue
        require(False, "unexpected sealed Python output: " + line)
    require(
        state == "complete"
        and successes == 1
        and reported == [24]
        and len(names) == len(set(names)) == 24
        and set(names) == set(SEALED_PYTHON_REQUIRED_NAMES),
        "sealed Python controls were omitted, replaced, duplicated, or not run",
    )
    return {
        "passed": 24,
        "failed": 0,
        "ignored_or_skipped": 0,
        "test_names": names,
        "scope": "actual memfd/SCM_RIGHTS/bootstrap/source/parser controls; no model execution",
    }


def save_summary(out: Path, manifest: dict) -> None:
    pending = out / "summary.json.pending"
    with pending.open("w") as stream:
        json.dump(manifest, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(pending, out / "summary.json")


def event(**values: object) -> None:
    print(json.dumps(values, sort_keys=True), flush=True)


def gate_commands(out: Path, sha: str) -> list[tuple[str, list[str]]]:
    cargo = ["cargo"]
    return [
        ("preflight", ["bash", "scripts/project-preflight.sh", "--audit"]),
        ("source-before", ["python3", "-B", "scripts/ci/verify_ci_source.py", "--kind", "head", "--expected-head", sha, "--output", str(out / "source-before.json")]),
        ("locked-graph", cargo + ["metadata", "--locked", "--offline", "--format-version", "1", "--manifest-path", "trillionnium/Cargo.toml"]),
        ("all-features-locked-graph", cargo + ["metadata", "--locked", "--offline", "--format-version", "1", "--manifest-path", "trillionnium/Cargo.toml", "--all-features"]),
        ("fuzz-locked-graph", cargo + ["metadata", "--locked", "--offline", "--format-version", "1", "--manifest-path", "tests/fuzz/Cargo.toml"]),
        ("format", cargo + ["fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all", "--", "--check"]),
        ("complete-version-vector", ["python3", "-B", "scripts/cell_complete_version_vector.py", "--check"]),
        ("complete-content-vector", ["python3", "-B", "scripts/cell_version_content_vector.py", "--check"]),
        ("version-retention-vector", ["python3", "-B", "scripts/cell_version_retention_v3_vector.py", "--check"]),
        ("storage-descriptor-vector", ["python3", "-B", "scripts/cell_storage_descriptor_reference.py", "--check"]),
        ("discovery-epoch-vector", ["python3", "-B", "scripts/cell_discovery_epoch_v3_vector.py", "--check"]),
        ("discovery-ci-controls", ["python3", "-B", "scripts/ci/test_cell_discovery_v3_ci.py"]),
        ("storage-convergence-ci-controls", ["python3", "-B", "scripts/ci/test_cell_storage_convergence_ci.py"]),
        ("sealed-research-python-controls", ["python3", "-B", "-m", "unittest", "discover", "-s", "scripts", "-p", "test_llm_cell_sealed_worker_v1.py", "-v"]),
        ("complete-da-native", cargo + ["test", "--locked", "--offline", "--manifest-path", "trillionnium/Cargo.toml", "-p", "trnm-data-availability", "--", "--test-threads=1"]),
        ("node-storage-owner-native", cargo + ["test", "--locked", "--offline", "--manifest-path", "trillionnium/Cargo.toml", "-p", "trnm-pon-node", "--lib", "store::storage_service::", "--", "--test-threads=1"]),
        ("strict-clippy", cargo + ["clippy", "--locked", "--offline", "--manifest-path", "trillionnium/Cargo.toml", "--workspace", "--all-targets", "--all-features", "--", "-D", "warnings"]),
        ("source-negative-controls", ["python3", "-B", "scripts/ci/test_ci_source_integrity.py"]),
        ("pq-negative-controls", ["python3", "-B", "scripts/ci/test_pq_research_integration.py"]),
        ("ci-contract-controls", ["python3", "-B", "scripts/ci/test_ci_contract.py"]),
        ("repository-links", ["python3", "-B", "scripts/ci/check_repository.py"]),
        ("pq-source-pins", ["python3", "-B", "scripts/ci/check_pq_research_integration.py"]),
        ("source-inventory", ["python3", "-B", "scripts/refresh_distributed_source_inventory.py", "--check"]),
        ("source-after", ["python3", "-B", "scripts/ci/verify_ci_source.py", "--kind", "head", "--expected-head", sha, "--output", str(out / "source-after.json")]),
        ("no-tracked-changes", ["git", "diff", "--exit-code"]),
    ]


class Runner:
    def __init__(self, cfg: dict, raw_config: bytes):
        self.cfg = cfg
        self.manifest = {
            "schema": "cell-storage-convergence-exact-source-ai395-gates-v1",
            "scope": "Linux x86_64; complete default-feature DA and filtered Node storage-owner runtime; all-feature graph/lint only; HOLD_NO_GO",
            "started_unix": time.time(), "passed": False, "state": "initializing",
            "configuration_sha256": hashlib.sha256(raw_config).hexdigest(),
            "commands": [], "setup_checks": [], "errors": [],
        }
        self.out = Path(cfg["out"])
        require(self.out.is_absolute(), "out must be absolute")
        self.user_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        self.work = (self.user_home / "work").resolve(strict=True)
        require(self.work.stat().st_uid == os.getuid(), "work directory is not user-owned")
        self.out = self.out.resolve()
        require(self.out.is_relative_to(self.work) and self.out != self.work,
                "out must be a task directory under the user's work directory")
        source = Path(cfg["root"]).resolve(strict=True)
        require(not self.out.is_relative_to(source) and not source.is_relative_to(self.out),
                "out overlaps the source checkout")
        self.out.mkdir(parents=True, exist_ok=False)
        frozen = self.out / "frozen-configuration.json"
        frozen.write_bytes(raw_config)
        self.manifest["frozen_configuration"] = file_identity(frozen)
        self.manifest["native_expectations"] = cfg["native_expectations"]
        save_summary(self.out, self.manifest)
        self.env = os.environ.copy()
        self.root = self.work
        self.provider_before = None

    def checkpoint(self) -> None:
        save_summary(self.out, self.manifest)

    def probe(self, label: str, command: list[str], *, env: dict | None = None) -> str:
        entry = {"label": label, "command": command, "exit_code": None}
        self.manifest["setup_checks"].append(entry)
        try:
            completed = subprocess.run(command, cwd=self.root, env=env or self.env,
                                       text=True, capture_output=True, timeout=30, check=False)
            entry.update(exit_code=completed.returncode, stdout=completed.stdout,
                         stderr=completed.stderr)
            require(completed.returncode == 0, label + " failed")
            return completed.stdout.strip()
        except BaseException as error:
            entry["error"] = type(error).__name__ + ": " + str(error)
            raise
        finally:
            self.checkpoint()

    def task_path(self, name: str, *, exists: bool = False) -> Path:
        raw = Path(self.cfg[name])
        require(raw.is_absolute(), name + " must be absolute")
        path = raw.resolve(strict=exists)
        require(path.is_relative_to(self.work) and path != self.work,
                name + " must be scoped under the user's work directory")
        return path

    def mount_receipt(self, label: str, path: Path, *, native: bool) -> dict:
        output = self.probe("mount-" + label,
                            ["findmnt", "--json", "-T", str(path), "-o", "TARGET,SOURCE,FSTYPE,OPTIONS"])
        mounts = json.loads(output)["filesystems"]
        require(len(mounts) == 1, "ambiguous mount for " + label)
        mount = mounts[0]
        usage = shutil.disk_usage(path)
        result = {"path": str(path), "mount": mount, "device_id": path.stat().st_dev,
                  "capacity_bytes": usage.total, "used_bytes": usage.used, "free_bytes": usage.free}
        if native:
            require(mount["fstype"] in LOCAL_FILESYSTEMS and mount["source"].startswith("/dev/"),
                    label + " must use a persistent local block filesystem, never tmpfs/overlay/NFS")
            require("noexec" not in mount.get("options", "").split(","),
                    label + " must allow execution on the persistent filesystem")
        return result

    def host_receipt(self) -> dict:
        receipt = {"sample_unix": time.time(), "hostname": platform.node(),
                   "system": platform.system(), "release": platform.release(),
                   "machine": platform.machine(), "uid": os.getuid(),
                   "nice": os.getpriority(os.PRIO_PROCESS, 0), "pressure": {}}
        for resource in ("cpu", "io", "memory"):
            path = Path("/proc/pressure") / resource
            receipt["pressure"][resource] = path.read_text().strip()
        group = next((line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines()
                      if line.startswith("0::")), None)
        require(group is not None and group.startswith("/") and ".." not in Path(group).parts,
                "missing canonical cgroup v2 path")
        directory = Path("/sys/fs/cgroup") / group.lstrip("/")
        receipt["task_cgroup"] = {"path": group}
        for name in ("cpu.max", "cpu.stat", "cpu.pressure", "memory.max", "memory.current",
                     "memory.peak", "memory.events", "io.pressure", "pids.current", "pids.peak"):
            path = directory / name
            receipt["task_cgroup"][name] = path.read_text().strip() if path.exists() else "unavailable"
        return receipt

    def validate_provider(self, phase: str) -> dict:
        provider, provider_identity = read_json_file(self.provider_path)
        require(provider.get("result") == "PASS", "provider validation did not pass")
        exports = provider.get("exports")
        require(isinstance(exports, dict) and set(exports) == PROVIDER_EXPORTS,
                "provider exports differ from the seven approved variables")
        require(all(isinstance(v, str) and "\n" not in v and "\r" not in v for v in exports.values()),
                "noncanonical provider export")
        require(exports["OPENSSL_STATIC"] == "1" and exports["OPENSSL_CONF"] == "/dev/null"
                and exports["TRNM_PQ_OPENSSL_VERSION"] == OPENSSL_VERSION,
                "provider static/version/config exports differ")
        prefix = Path(exports["OPENSSL_DIR"])
        require(prefix.is_absolute() and prefix.resolve(strict=True) == prefix
                and prefix.is_relative_to(self.work), "provider prefix must be canonical under work")
        require(exports["TRNM_PQ_OPENSSL"] == str(prefix / "bin/openssl")
                and exports["OPENSSL_MODULES"] == str(prefix / "lib/ossl-modules"),
                "provider paths are not bound to the prefix")
        receipt, receipt_identity = read_json_file(self.provider_receipt_path)
        require(provider.get("provider_receipt_sha256") == receipt_identity["sha256"],
                "provider receipt hash mismatch")
        require(receipt.get("schema") == "trnm-ci-pq-provider-v3"
                and receipt.get("result") == "PREPARED_AND_SMOKE_VERIFIED"
                and receipt.get("exit_code") == 0 and receipt.get("last_stage") == "complete"
                and receipt.get("version") == OPENSSL_VERSION, "provider preparation receipt failed")
        for key in ("backend_exported", "source_digest_verified", "static_build",
                    "ml_dsa_65_sign_verify_and_wrong_message_rejection"):
            require(receipt.get(key) is True, "provider receipt lacks " + key)
        for key in ("native_rust_pq_tests_run_by_preparation", "independent_cryptographic_implementation_claim",
                    "whole_chain_quantum_security_qualified", "production_activation"):
            require(receipt.get(key) is False, "provider receipt scope changed: " + key)
        require(receipt.get("source_archive_sha256_expected") == OPENSSL_ARCHIVE_SHA256,
                "provider archive pin differs")
        preparation = file_identity(self.root / "scripts/ci/prepare_pq_provider.sh")
        require(receipt.get("preparation_script_sha256") == preparation["sha256"],
                "provider preparation script differs from the tested source")
        require(receipt.get("install_prefix") == str(prefix)
                and receipt.get("cli_executable") == exports["TRNM_PQ_OPENSSL"]
                and receipt.get("cli_sha256") == exports["TRNM_PQ_OPENSSL_SHA256"]
                and receipt.get("openssl_conf") == exports["OPENSSL_CONF"]
                and receipt.get("openssl_modules") == exports["OPENSSL_MODULES"],
                "provider receipt and exports disagree")
        rows = receipt.get("native_backend_inputs")
        require(isinstance(rows, list) and len(rows) == len(PROVIDER_INPUTS), "provider input list differs")
        identities = [file_identity(prefix / relative) for relative in PROVIDER_INPUTS]
        require(all(isinstance(row, dict) for row in rows), "invalid provider input row")
        expected = {row.get("path"): row for row in rows}
        require(len(expected) == len(identities) and set(expected) == {row["path"] for row in identities},
                "provider input paths differ")
        for identity in identities:
            pinned = expected[identity["path"]]
            require(pinned.get("sha256") == identity["sha256"] and pinned.get("bytes") == identity["bytes"],
                    "provider input hash/size mismatch: " + identity["path"])
        require(identities[0]["sha256"] == exports["TRNM_PQ_OPENSSL_SHA256"], "provider CLI pin differs")
        environment = self.env | exports
        version = self.probe("provider-version-" + phase, [exports["TRNM_PQ_OPENSSL"], "version"], env=environment)
        require(version.startswith("OpenSSL " + OPENSSL_VERSION + " ")
                and version == provider.get("version") == receipt.get("cli_version_output"),
                "actual provider version differs from its receipts")
        return {"validation_file": provider_identity, "receipt_file": receipt_identity,
                "preparation_script": preparation, "exports": exports, "actual_version": version,
                "native_backend_inputs": identities, "receipt": receipt}

    def prepare(self) -> None:
        require(platform.system() == "Linux" and platform.machine() == "x86_64", "expected Linux x86_64")
        self.root = self.task_path("root", exists=True)
        self.target = self.task_path("target")
        self.native_tmp = self.task_path("native_tmp")
        self.provider_path = self.task_path("provider_path", exists=True)
        receipt_default = self.provider_path.parent / "observations/pq-provider/provider.json"
        self.cfg["provider_receipt_path"] = self.cfg.get("provider_receipt_path", str(receipt_default))
        self.provider_receipt_path = self.task_path("provider_receipt_path", exists=True)
        self.synthetic_root = Path(self.cfg.get("synthetic_tmp_root", "/dev/shm")).resolve(strict=True)
        require(self.synthetic_root == Path("/dev/shm").resolve(strict=True), "synthetic root must be /dev/shm")
        for name, path in (("out", self.out), ("target", self.target), ("native_tmp", self.native_tmp)):
            require(not path.is_relative_to(self.root) and not self.root.is_relative_to(path),
                    name + " overlaps the source checkout")
        require(len({self.out, self.target, self.native_tmp}) == 3, "task output paths must differ")
        require(not any(a.is_relative_to(b) or b.is_relative_to(a)
                        for a, b in ((self.out, self.target), (self.out, self.native_tmp),
                                     (self.target, self.native_tmp))), "task output directories overlap")
        self.target.mkdir(parents=True, exist_ok=True)
        self.native_tmp.mkdir(parents=True, exist_ok=True)
        require(not any(self.native_tmp.iterdir()), "native_tmp must be an unused isolated directory")
        for path in (self.root, self.out, self.target, self.native_tmp):
            require(path.stat().st_uid == os.getuid(), "task directory is not user-owned: " + str(path))
        self.sha = self.cfg["sha"]
        require(isinstance(self.sha, str) and re.fullmatch(r"[0-9a-f]{40}", self.sha) is not None,
                "expected commit must be a canonical SHA-1")
        require(isinstance(self.cfg["tree"], str)
                and re.fullmatch(r"[0-9a-f]{40}", self.cfg["tree"]) is not None,
                "expected tree must be a canonical SHA-1")
        self.env, removed = scrub_environment(self.env)
        self.cargo_home = Path(self.env.get("CARGO_HOME", str(self.user_home / ".cargo")))
        require(self.cargo_home.is_absolute(), "CARGO_HOME must be absolute")
        self.cargo_home = self.cargo_home.resolve(strict=True)
        self.env["CARGO_HOME"] = str(self.cargo_home)
        self.env.update(RUSTUP_TOOLCHAIN=TOOLCHAIN, RUSTUP_AUTO_INSTALL="0", RUSTUP_SKIP_UPDATE_CHECK="1",
                        CARGO_BUILD_JOBS="2", CARGO_TARGET_DIR=str(self.target), CARGO_TERM_COLOR="never",
                        RUST_TEST_THREADS="1", PYTHONDONTWRITEBYTECODE="1", LC_ALL="C",
                        GIT_OPTIONAL_LOCKS="0", GIT_NO_REPLACE_OBJECTS="1", GIT_TERMINAL_PROMPT="0",
                        TMPDIR=str(self.native_tmp), TMP=str(self.native_tmp), TEMP=str(self.native_tmp))
        self.manifest.update(commit=self.sha, paths={key: str(getattr(self, key)) for key in
                             ("root", "out", "target", "native_tmp", "provider_path", "provider_receipt_path")},
                             removed_inherited_environment_names=removed)
        self.manifest["mounts_before"] = {name: self.mount_receipt(name, path, native=True)
                                           for name, path in (("root", self.root), ("out", self.out),
                                                              ("target", self.target), ("native_tmp", self.native_tmp))}
        self.manifest["host_before"] = self.host_receipt()
        self.manifest["block_devices"] = []
        devices = sorted({value["mount"]["source"].split("[", 1)[0]
                          for value in self.manifest["mounts_before"].values()})
        for device in devices:
            info = self.probe("block-device", ["lsblk", "--json", "--inverse", "--output", "NAME,TYPE,ROTA,TRAN,SIZE", device])
            self.manifest["block_devices"].append({"source": device, "device": json.loads(info)})
        self.manifest["cargo_config_before"] = cargo_config_inputs(self.root, self.cargo_home)
        toolchain = {}
        rustup_raw = Path(self.cfg.get("rustup", str(self.user_home / ".cargo/bin/rustup")))
        require(rustup_raw.is_absolute(), "rustup must be an absolute executable path")
        rustup = rustup_raw.resolve(strict=True)
        require(os.access(rustup, os.X_OK), "rustup is not executable")
        toolchain["rustup"] = file_identity(rustup)
        self.env["PATH"] = str(rustup_raw.parent) + os.pathsep + self.env.get("PATH", os.defpath)
        for name in ("rustc", "cargo"):
            executable = self.probe(name + "-path", [str(rustup), "which", "--toolchain", TOOLCHAIN, name])
            path = Path(executable).resolve(strict=True)
            toolchain[name] = file_identity(path)
        bindir = str(Path(toolchain["cargo"]["path"]).parent)
        require(Path(toolchain["rustc"]["path"]).parent == Path(bindir), "compiler and Cargo toolchain differ")
        self.env["PATH"] = bindir + os.pathsep + self.env.get("PATH", os.defpath)
        for name, flag in (("rustc", "-vV"), ("cargo", "-Vv")):
            version = self.probe(name + "-actual-version", [name, flag])
            require(re.search(r"(?m)^release: " + re.escape(TOOLCHAIN) + r"$", version) is not None,
                    name + " is not actually " + TOOLCHAIN)
            require("host: x86_64-unknown-linux-gnu" in version, name + " host differs")
            toolchain[name]["version_output"] = version
        self.manifest["toolchain"] = toolchain
        self.tree = self.probe("initial-tree", ["git", "rev-parse", "HEAD^{tree}"])
        require(Path(self.probe("initial-root", ["git", "rev-parse", "--show-toplevel"])).resolve() == self.root,
                "Git worktree differs from the configured source root")
        require(self.probe("initial-head", ["git", "rev-parse", "HEAD"]) == self.sha, "HEAD mismatch")
        require("tree" not in self.cfg or self.cfg["tree"] == self.tree, "expected tree mismatch")
        require(not self.probe("initial-clean-source", ["git", "status", "--porcelain", "--untracked-files=all", "--ignore-submodules=none"]),
                "source is not initially clean")
        self.manifest["tree"] = self.tree
        self.manifest["runner_before"] = file_identity(Path(__file__).resolve(strict=True))
        self.provider_before = self.validate_provider("before")
        self.manifest["provider_before"] = self.provider_before
        self.env.update(self.provider_before["exports"])
        environment_keys = ("RUSTUP_TOOLCHAIN", "RUSTUP_AUTO_INSTALL", "CARGO_HOME", "CARGO_BUILD_JOBS", "CARGO_TARGET_DIR",
                            "CARGO_TERM_COLOR", "RUST_TEST_THREADS", "PYTHONDONTWRITEBYTECODE", "LC_ALL",
                            "GIT_OPTIONAL_LOCKS", "GIT_NO_REPLACE_OBJECTS", "GIT_TERMINAL_PROMPT",
                            "TMPDIR", "TMP", "TEMP", "PATH")
        self.manifest["command_environment"] = {key: self.env[key] for key in environment_keys}
        self.manifest["command_environment"].update(self.provider_before["exports"])
        self.manifest["state"] = "running"
        self.checkpoint()

    def run_gate(self, label: str, command: list[str]) -> dict:
        entry = {"label": label, "command": command, "state": "running", "exit_code": None,
                 "started_unix": time.time(), "errors": []}
        self.manifest["commands"].append(entry)
        self.checkpoint()
        event(event="start", label=label, command=command)
        started = time.monotonic()
        stdout, stderr = self.out / (label + ".stdout.log"), self.out / (label + ".stderr.log")
        environment = self.env.copy()
        temporary = None
        blocked_log = None
        interrupted = None
        try:
            if label in SYNTHETIC:
                mount = self.mount_receipt(label + "-scratch", self.synthetic_root, native=False)
                require(mount["mount"]["fstype"] == "tmpfs", "synthetic scratch is not tmpfs")
                require(mount["free_bytes"] > 4 * 1024 ** 3, "insufficient synthetic-control scratch")
                temporary = tempfile.TemporaryDirectory(prefix="trnm-cell-ci-negative-" + label + "-", dir=self.synthetic_root)
                scratch = Path(temporary.name)
                guards = self.out / (label + "-blocked-native-tools")
                guards.mkdir()
                blocked_log = self.out / (label + ".blocked-native-tools.log")
                blocked_log.touch(exist_ok=False)
                wrapper = '#!/bin/sh\nprintf "%s\\n" "$0" >> "$TRNM_SYNTHETIC_EXEC_AUDIT"\nprintf "%s\\n" "native Rust tool forbidden in synthetic tmpfs control" >&2\nexit 125\n'
                for name in BLOCKED_TOOLS:
                    path = guards / name
                    path.write_text(wrapper)
                    path.chmod(0o755)
                probe_log = self.out / (label + ".native-tool-guard-probe.log")
                probe_log.touch(exist_ok=False)
                probe_environment = environment | {"TRNM_SYNTHETIC_EXEC_AUDIT": str(probe_log)}
                entry["native_tool_guard_probes"] = []
                for name in BLOCKED_TOOLS:
                    result = subprocess.run([str(guards / name), "--version"], cwd=self.root,
                                            env=probe_environment, capture_output=True, timeout=10, check=False)
                    entry["native_tool_guard_probes"].append({"tool": name, "exit_code": result.returncode,
                                                             "guard": file_identity(guards / name)})
                    require(result.returncode == 125, "synthetic native-tool guard is not executable")
                require(probe_log.read_text().splitlines() == [str(guards / name) for name in BLOCKED_TOOLS],
                        "native-tool guard probe audit is incomplete")
                environment.update(TMPDIR=str(scratch), TMP=str(scratch), TEMP=str(scratch),
                                   PATH=str(guards) + os.pathsep + environment["PATH"],
                                   TRNM_SYNTHETIC_EXEC_AUDIT=str(blocked_log))
                entry.update(temporary_filesystem="tmpfs synthetic Python controls only", scratch_mount=mount,
                             blocked_tool_names=list(BLOCKED_TOOLS))
            else:
                entry["temporary_filesystem"] = "verified persistent local block filesystem"
            entry["environment_overrides"] = {key: environment[key] for key in
                                                ("TMPDIR", "TMP", "TEMP", "RUSTUP_TOOLCHAIN", "CARGO_TARGET_DIR", "PATH")}
            self.checkpoint()
            with stdout.open("xb") as so, stderr.open("xb") as se:
                completed = subprocess.run(command, cwd=self.root, env=environment, stdout=so, stderr=se, check=False)
                entry["exit_code"] = completed.returncode
        except BaseException as error:
            entry["errors"].append(type(error).__name__ + ": " + str(error))
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                interrupted = error
        finally:
            if blocked_log is not None:
                try:
                    entry["blocked_native_tool_attempts"] = blocked_log.read_text().splitlines()
                    if entry["blocked_native_tool_attempts"]:
                        entry["errors"].append("native tool execution attempted in synthetic tmpfs control")
                except OSError as error:
                    entry["errors"].append("guard audit failed: " + str(error))
            if temporary is not None:
                try:
                    temporary.cleanup()
                    entry["temporary_cleanup"] = "completed"
                except OSError as error:
                    entry["errors"].append("temporary cleanup failed: " + str(error))
                    entry["temporary_cleanup"] = "failed"
            for name, path in (("stdout", stdout), ("stderr", stderr)):
                try:
                    identity = file_identity(path)
                    entry[name + "_sha256"] = identity["sha256"]
                    entry[name + "_bytes"] = identity["bytes"]
                    entry[name + "_path"] = str(path)
                except (OSError, GateError) as error:
                    entry["errors"].append(name + " log unavailable: " + str(error))
            if label in REQUIRED_NEW_TESTS and stdout.exists():
                with stdout.open(errors="replace") as stream:
                    entry["native_result_lines"] = [line.rstrip("\n") for line in stream if line.startswith("test result:")]
                try:
                    if label == "complete-da-native":
                        entry["retained_unfiltered_native_check"] = native_results(entry["native_result_lines"])
                    entry["native_execution"] = exact_native_execution(
                        stdout.read_text(errors="replace"), self.cfg["native_expectations"][label], label)
                except GateError as error:
                    entry["errors"].append(str(error))
            if label == "sealed-research-python-controls":
                try:
                    entry["python_execution"] = exact_sealed_python_execution(
                        stdout.read_text(errors="strict") + stderr.read_text(errors="strict"))
                except (GateError, OSError, UnicodeError) as error:
                    entry["errors"].append("sealed Python execution: " + str(error))
            entry["elapsed_seconds"] = time.monotonic() - started
            entry["state"] = "passed" if entry["exit_code"] == 0 and not entry["errors"] else "failed"
            self.checkpoint()
            event(event="finish", **entry)
        if interrupted is not None:
            raise interrupted
        return entry

    def verify_final_state(self) -> None:
        require(file_identity(self.out / "frozen-configuration.json") == self.manifest["frozen_configuration"],
                "frozen configuration changed during the gates")
        before, before_id = read_json_file(self.out / "source-before.json")
        after, after_id = read_json_file(self.out / "source-after.json")
        require(before == after and before_id["sha256"] == after_id["sha256"], "source-before differs from source-after")
        require(before.get("schema") == "trnm-ci-source-v1" and before.get("kind") == "head"
                and before.get("tested_commit") == before.get("candidate") == self.sha
                and before.get("tested_tree") == self.tree and before.get("tracked_worktree_verified") is True
                and before.get("tests_executed_by_identity_check") is False,
                "source receipt does not prove the exact tracked worktree")
        self.manifest["source_receipts_equal"] = True
        self.manifest["source_receipt_sha256"] = before_id["sha256"]
        self.manifest["final_status_porcelain"] = self.probe("final-clean-source", ["git", "status", "--porcelain", "--untracked-files=all", "--ignore-submodules=none"])
        require(not self.manifest["final_status_porcelain"], "source is not finally clean")
        require(self.probe("final-head", ["git", "rev-parse", "HEAD"]) == self.sha
                and self.probe("final-tree", ["git", "rev-parse", "HEAD^{tree}"]) == self.tree,
                "final Git identity changed")
        self.manifest["provider_after"] = self.validate_provider("after")
        require(self.manifest["provider_after"] == self.provider_before, "provider inputs changed during the gates")
        self.manifest["provider_inputs_unchanged"] = True
        self.manifest["cargo_config_after"] = cargo_config_inputs(self.root, self.cargo_home)
        require(self.manifest["cargo_config_before"] == self.manifest["cargo_config_after"],
                "Cargo configuration changed during the gates")
        self.manifest["runner_after"] = file_identity(Path(__file__).resolve(strict=True))
        require(self.manifest["runner_before"] == self.manifest["runner_after"], "runner changed during the gates")
        self.manifest["mounts_after"] = {name: self.mount_receipt(name + "-after", Path(value["path"]), native=True)
                                         for name, value in self.manifest["mounts_before"].items()}
        for name, value in self.manifest["mounts_before"].items():
            after_mount = self.manifest["mounts_after"][name]
            require(value["device_id"] == after_mount["device_id"] and value["mount"] == after_mount["mount"],
                    "task filesystem changed during the gates: " + name)
        self.manifest["host_after"] = self.host_receipt()

    def run(self) -> int:
        try:
            self.prepare()
            blocked = None
            for label, command in gate_commands(self.out, self.sha):
                if blocked is not None and label not in ("source-after", "no-tracked-changes"):
                    self.manifest["commands"].append({"label": label, "command": command,
                                                      "state": "not-run", "exit_code": None, "reason": blocked})
                    self.checkpoint()
                    continue
                result = self.run_gate(label, command)
                if label in ("preflight", "source-before") and result["state"] != "passed":
                    blocked = label + " did not pass; unverified source cannot execute the remaining gates"
            self.verify_final_state()
            expected_labels = [label for label, _ in gate_commands(self.out, self.sha)]
            require(len(expected_labels) == 25, "convergence gate union changed unexpectedly")
            self.manifest["passed"] = [row["label"] for row in self.manifest["commands"]] == expected_labels and all(
                row["state"] == "passed" for row in self.manifest["commands"])
        except BaseException as error:
            self.manifest["errors"].append(type(error).__name__ + ": " + str(error))
            (self.out / "runner-error.log").write_text(traceback.format_exc())
            self.manifest["passed"] = False
        finally:
            self.manifest["state"] = "passed" if self.manifest["passed"] else "failed"
            self.manifest["finished_unix"] = time.time()
            self.checkpoint()
            event(event="complete", passed=self.manifest["passed"], state=self.manifest["state"],
                  commands=len(self.manifest["commands"]), commit=self.cfg.get("sha"), out=str(self.out),
                  errors=self.manifest["errors"])
        return 0 if self.manifest["passed"] else 1


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024, "configuration exceeds 1 MiB")
        cfg = json_load(raw)
        require(set(cfg) <= {"root", "out", "target", "provider_path", "native_tmp", "sha", "tree",
                             "provider_receipt_path", "synthetic_tmp_root", "rustup", "native_expectations"},
                "unknown configuration key")
        require({"root", "out", "target", "provider_path", "native_tmp", "sha", "tree", "native_expectations"} <= set(cfg),
                "missing required configuration key")
        require(all(isinstance(value, str) and value for key, value in cfg.items() if key != "native_expectations"),
                "path/source configuration values must be nonempty strings")
        validate_native_expectations(cfg["native_expectations"])
        return Runner(cfg, raw).run()
    except BaseException as error:
        event(event="runner-initialization-failed", passed=False, error=type(error).__name__ + ": " + str(error))
        traceback.print_exc(file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
