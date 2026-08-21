#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
POCO_WORKFLOW="$ROOT/.github/workflows/trnm-poco-bft-v0.yml"
LEGACY_WORKFLOW="$ROOT/.github/workflows/rust-l1-testnet-preflight.yml"
RECOVERY_GATE="$ROOT/scripts/ci/check_poco_bft_v0_recovery_smoke.sh"
G3_LAN_FLEET_GATE="$ROOT/scripts/ci/check_poco_g3_lan_fleet.sh"
G3_SOURCE_CANDIDATE_PREPARE="$ROOT/scripts/poco-fleet/prepare_source_candidate.py"
G3_SOURCE_CANDIDATE_CHECK="$ROOT/scripts/poco-fleet/check_source_candidate.py"
G3_REPRODUCIBLE_CANDIDATE_BUILD="$ROOT/scripts/poco-fleet/build_reproducible_lab_candidate.py"
G3_REPRODUCIBLE_BUILD_REPORT_ASSEMBLER="$ROOT/scripts/poco-fleet/assemble_reproducible_build_report.py"
G3_STAGE0_OBSERVATION_STATUS="$ROOT/scripts/poco-fleet/check_stage0_observation_status.py"
G3_STAGE0_STATUS="$ROOT/docs/evidence/poco-g3/status.toml"
G3_FRESH_CLONE_GATES_REPORT="$ROOT/docs/evidence/poco-g3/stage0-repro-d6bb34c1-20260820/fresh-clone-gates-report.json"
G3_RUST_SRC_CROSS_TIME_REPORT="$ROOT/docs/evidence/poco-g3/stage0-repro-d6bb34c1-20260820/rust-src-cross-time-control-report.json"
G3_RUST_SRC_DRIFT_REPORT="$ROOT/docs/evidence/poco-g3/stage0-repro-d6bb34c1-20260820/rust-src-drift-build-report.json"
G3_RUST_SRC_REMAP_CONTROL_REPORT="$ROOT/docs/evidence/poco-g3/stage0-repro-d6bb34c1-20260820/rust-src-remapped-v2-committed-control-build-report.json"
G3_FAULT_RESTART_RUNNER="$ROOT/scripts/poco-fleet/run_fault_restart_fleet_v1.py"
G3_FAULT_RESTART_HANDOFF_TEST="$ROOT/scripts/poco-fleet/run_fault_restart_handoff_v1_test.py"
G3_LAB_CONSENSUS_RUNTIME="$ROOT/trillionnium/crates/trnm-poco-lab-validator/src/consensus_runtime.rs"
LEGACY_PREFLIGHT="$ROOT/trillionnium/scripts/testnet_preflight.sh"
CORE_SOURCE="$ROOT/trillionnium/crates/trnm-consensus-core/src/core.rs"
CORE_TESTS="$ROOT/trillionnium/crates/trnm-consensus-core/src/tests.rs"
APP_RECOVERY="$ROOT/trillionnium/crates/trnm-consensus-app/src/native_validation_recovery.rs"
APP_STORE_SOURCE="$ROOT/trillionnium/crates/trnm-consensus-app/src/store.rs"
LEGACY_APP_CARGO="$ROOT/trillionnium/crates/trnm-consensus-app/Cargo.toml"
LEGACY_APP_LOCK="$ROOT/trillionnium/crates/trnm-consensus-app/Cargo.lock"
SAFETY_STORE_SOURCE="$ROOT/trillionnium/crates/trnm-consensus-safety-store/src/sqlite.rs"
NODE_SOURCE="$ROOT/trillionnium/crates/trnm-poco-node/src/lib.rs"
NODE_TIMEOUT_SOURCE="$ROOT/trillionnium/crates/trnm-poco-node/src/ordinary_timeout.rs"
NODE_RECOVERY_TESTS="$ROOT/trillionnium/crates/trnm-poco-node/src/recovery_tests.rs"
NODE_PROCESS_KILL_HELPER="$ROOT/trillionnium/crates/trnm-poco-node/src/bin/trnm-poco-recovery-kill-helper.rs"
NODE_PROCESS_KILL_TEST="$ROOT/trillionnium/crates/trnm-poco-node/tests/recovery_process_kill_matrix.rs"
NODE_TIMEOUT_PROCESS_KILL_HELPER="$ROOT/trillionnium/crates/trnm-poco-node/src/bin/trnm-poco-timeout-signing-kill-helper.rs"
NODE_TIMEOUT_PROCESS_KILL_TEST="$ROOT/trillionnium/crates/trnm-poco-node/tests/timeout_signing_process_kill_matrix.rs"
NODE_PROCESS_WATERMARK="$ROOT/trillionnium/crates/trnm-poco-node/src/recovery_process_watermark.rs"
NODE_CARGO="$ROOT/trillionnium/crates/trnm-poco-node/Cargo.toml"
G1C_TRUTH="$ROOT/docs/protocol/poco-bft-v0/IMPLEMENTATION_GAP_REGISTER.md"
ROOT_README="$ROOT/README.md"
RELEASE_TRUTH="$ROOT/RELEASE_READINESS.md"
PROTOCOL_README="$ROOT/docs/protocol/poco-bft-v0/README.md"
CONSENSUS_SAFETY_DOC="$ROOT/docs/protocol/poco-bft-v0/02-chained-qc-consensus.md"
WIRE_DOC="$ROOT/docs/protocol/poco-bft-v0/03-wire-crypto-and-domain-separation.md"
INVARIANTS_DOC="$ROOT/docs/protocol/poco-bft-v0/07-invariants-and-conformance.md"
DELIVERY_PLAN="$ROOT/docs/development/TRNM_POCO_BFT_DELIVERY_PLAN_2026-08-04.md"
DUAL_TRACK_DECISION="$ROOT/docs/architecture/TRNM_CONSENSUS_DELIVERY_DUAL_TRACK_DECISION_2026-08-11.md"
PRODUCTION_CONTRACTS="$ROOT/docs/architecture/TRNM_POCO_BFT_PRODUCTION_CONTRACTS_V0.md"

fail() {
  printf 'PoCO-BFT CI/readiness truth gate failed: %s\n' "$*" >&2
  exit 1
}

require_file() {
  local path="$1"
  [[ -f "$path" ]] || fail "missing file: $path"
}

require_tracked() {
  local path="$1"
  local relative="${path#$ROOT/}"
  git -C "$ROOT" cat-file -e ":$relative" 2>/dev/null \
    || fail "required source is absent from the candidate index: $relative"
  git -C "$ROOT" diff --quiet -- "$relative" \
    || fail "required candidate index differs from the current working source: $relative"
}

require_g3_gate_authority_index() {
  local relative
  local required_list

  require_file "$G3_LAN_FLEET_GATE"
  require_tracked "$G3_LAN_FLEET_GATE"
  if ! required_list="$(python3 - "$G3_LAN_FLEET_GATE" <<'PY'
import pathlib
import re
import sys

gate = pathlib.Path(sys.argv[1])
text = gate.read_text(encoding="utf-8")
match = re.search(
    r"(?ms)^readonly -a REQUIRED_FILES=\(\n(?P<body>.*?)^\)\n",
    text,
)
if match is None:
    raise SystemExit(
        "G3 Stage0 contract self-test gate lost its exact REQUIRED_FILES authority array"
    )
paths = []
for line in match.group("body").splitlines():
    item = re.fullmatch(r'  "([^"]+)"', line)
    if item is None:
        raise SystemExit(f"non-canonical G3 REQUIRED_FILES entry: {line!r}")
    relative = item.group(1)
    path = pathlib.PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts or relative in paths:
        raise SystemExit(f"unsafe or duplicate G3 REQUIRED_FILES entry: {relative!r}")
    paths.append(relative)
if not paths:
    raise SystemExit("G3 REQUIRED_FILES must not be empty")
print("\n".join(paths))
PY
  )"; then
    fail "cannot parse the G3 Stage0 contract self-test authority set"
  fi
  while IFS= read -r relative; do
    require_file "$ROOT/$relative"
    require_tracked "$ROOT/$relative"
  done <<<"$required_list"
}

require_legacy_recovery_archive_guard() {
  if ! python3 - "$RECOVERY_GATE" <<'PY'
import pathlib
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
guard = 'if [[ "${TRNM_RUN_LEGACY_APP_ARCHIVE_TESTS:-0}" == "1" ]]; then'
if text.count(guard) != 1:
    raise SystemExit("recovery smoke must contain exactly one legacy archive guard")
start = text.index(guard)
end = text.index("\nelse\n", start)
for marker in ("run_unit_filter trnm-consensus-app ",):
    positions = []
    offset = 0
    while True:
        found = text.find(marker, offset)
        if found < 0:
            break
        positions.append(found)
        offset = found + len(marker)
    if not positions or any(position <= start or position >= end for position in positions):
        raise SystemExit(f"legacy recovery invocation escaped archive guard: {marker!r}")
for forbidden in (
    "run_feature_unit_filter trnm-poco-node recovery-test-support ",
    "  recovery_process_kill_matrix \\",
):
    if forbidden in text:
        raise SystemExit(f"non-buildable legacy Node recovery invocation remains: {forbidden!r}")
active_timeout = "  timeout_signing_process_kill_matrix \\"
if text.count(active_timeout) != 1 or text.index(active_timeout) >= start:
    raise SystemExit("active timeout SIGKILL matrix must execute before the legacy guard")
PY
  then
    fail "legacy recovery tests are not confined to the explicit archive opt-in"
  fi
}

require_literal() {
  local path="$1"
  local literal="$2"
  grep -Fq -- "$literal" "$path" \
    || fail "missing required literal in ${path#$ROOT/}: $literal"
}

require_literal_count() {
  local path="$1"
  local literal="$2"
  local expected="$3"
  local actual
  actual="$(grep -Fc -- "$literal" "$path" || true)"
  [[ "$actual" = "$expected" ]] \
    || fail "expected $expected occurrences in ${path#$ROOT/}, found $actual: $literal"
}

require_toml_target_feature() {
  local path="$1"
  local target_kind="$2"
  local target_name="$3"
  local required_feature="$4"
  if ! python3 - "$path" "$target_kind" "$target_name" "$required_feature" <<'PY'
import pathlib
import sys
import tomllib

path = pathlib.Path(sys.argv[1])
target_kind = sys.argv[2]
target_name = sys.argv[3]
required_feature = sys.argv[4]
with path.open("rb") as source:
    document = tomllib.load(source)
matches = [
    target
    for target in document.get(target_kind, [])
    if target.get("name") == target_name
]
if len(matches) != 1:
    raise SystemExit(
        f"expected exactly one [[{target_kind}]] named {target_name}, found {len(matches)}"
    )
actual = matches[0].get("required-features")
if actual != [required_feature]:
    raise SystemExit(
        f"[[{target_kind}]] {target_name} required-features={actual!r}, "
        f"expected [{required_feature!r}]"
    )
PY
  then
    fail "target $target_kind/$target_name is not gated only by $required_feature"
  fi
}

reject_literal() {
  local path="$1"
  local literal="$2"
  if grep -Fq -- "$literal" "$path"; then
    fail "forbidden readiness claim in ${path#$ROOT/}: $literal"
  fi
}

for required in \
  "$POCO_WORKFLOW" \
  "$LEGACY_WORKFLOW" \
  "$RECOVERY_GATE" \
  "$G3_STAGE0_OBSERVATION_STATUS" \
  "$G3_STAGE0_STATUS" \
  "$G3_FRESH_CLONE_GATES_REPORT" \
  "$G3_RUST_SRC_CROSS_TIME_REPORT" \
  "$G3_RUST_SRC_DRIFT_REPORT" \
  "$G3_RUST_SRC_REMAP_CONTROL_REPORT" \
  "$LEGACY_PREFLIGHT" \
  "$CORE_SOURCE" \
  "$CORE_TESTS" \
  "$APP_RECOVERY" \
  "$APP_STORE_SOURCE" \
  "$LEGACY_APP_CARGO" \
  "$LEGACY_APP_LOCK" \
  "$SAFETY_STORE_SOURCE" \
  "$NODE_SOURCE" \
  "$NODE_TIMEOUT_SOURCE" \
  "$NODE_RECOVERY_TESTS" \
  "$NODE_PROCESS_KILL_HELPER" \
  "$NODE_PROCESS_KILL_TEST" \
  "$NODE_TIMEOUT_PROCESS_KILL_HELPER" \
  "$NODE_TIMEOUT_PROCESS_KILL_TEST" \
  "$NODE_PROCESS_WATERMARK" \
  "$NODE_CARGO" \
  "$G1C_TRUTH" \
  "$ROOT_README" \
  "$RELEASE_TRUTH" \
  "$PROTOCOL_README" \
  "$CONSENSUS_SAFETY_DOC" \
  "$WIRE_DOC" \
  "$INVARIANTS_DOC" \
  "$DELIVERY_PLAN" \
  "$DUAL_TRACK_DECISION" \
  "$PRODUCTION_CONTRACTS"; do
  require_file "$required"
done

# The Stage0 contract self-test gate is itself candidate-index authority, and
# every source in its canonical REQUIRED_FILES array must be present and
# byte-identical to the candidate index. This prevents a dirty local fixture
# from validating truth that the candidate commit would not ship.
require_g3_gate_authority_index
require_tracked "$G3_STAGE0_STATUS"
require_tracked "$G3_FRESH_CLONE_GATES_REPORT"
require_tracked "$G3_RUST_SRC_CROSS_TIME_REPORT"
require_tracked "$G3_RUST_SRC_DRIFT_REPORT"
require_tracked "$G3_RUST_SRC_REMAP_CONTROL_REPORT"
require_legacy_recovery_archive_guard

# A SafetyStore change must trigger both pull-request and main-push PoCO gates.
require_literal_count "$POCO_WORKFLOW" \
  '      - "trillionnium/crates/trnm-consensus-safety-store/**"' 2
require_literal_count "$POCO_WORKFLOW" \
  '      - "trillionnium/crates/trnm-consensus-signer-journal/**"' 2
require_literal_count "$POCO_WORKFLOW" \
  '      - ".github/workflows/rust-l1-testnet-preflight.yml"' 2
require_literal_count "$POCO_WORKFLOW" \
  '      - "trillionnium/scripts/testnet_preflight.sh"' 2
require_literal_count "$POCO_WORKFLOW" \
  '      - "RELEASE_READINESS.md"' 2
require_literal_count "$POCO_WORKFLOW" \
  '      - "README.md"' 2
require_literal_count "$POCO_WORKFLOW" \
  '      - "docs/architecture/TRNM_CONSENSUS_DELIVERY_DUAL_TRACK_DECISION_2026-08-11.md"' 2
require_literal_count "$POCO_WORKFLOW" \
  '      - "docs/architecture/TRNM_POCO_BFT_PRODUCTION_CONTRACTS_V0.md"' 2
require_literal_count "$POCO_WORKFLOW" \
  '      - "docs/development/TRNM_POCO_BFT_DELIVERY_PLAN_2026-08-04.md"' 2
require_literal_count "$POCO_WORKFLOW" \
  '      - "docs/protocol/poco-bft-v0/**"' 2
require_literal_count "$POCO_WORKFLOW" \
  '      - "scripts/ci/check_poco_bft_v0_*"' 2
require_literal_count "$POCO_WORKFLOW" \
  '      - "trillionnium/crates/trnm-poco-node/**"' 2

# SafetyStore is a first-class package in the complete test, strict lint,
# recovery, and release-profile compilation boundaries.
require_literal "$POCO_WORKFLOW" \
  'cargo test --locked -p trnm-consensus-safety-store --lib --tests'
require_literal "$POCO_WORKFLOW" \
  'cargo clippy --locked -p trnm-consensus-safety-store --all-targets -- -D warnings'
require_literal "$POCO_WORKFLOW" \
  '            -p trnm-consensus-safety-store \'
require_literal "$POCO_WORKFLOW" \
  'cargo test --locked -p trnm-consensus-signer-journal --all-targets'
require_literal "$POCO_WORKFLOW" \
  'cargo clippy --locked -p trnm-consensus-signer-journal --all-targets -- -D warnings'
require_literal "$POCO_WORKFLOW" \
  '            -p trnm-consensus-signer-journal \'
require_literal "$POCO_WORKFLOW" \
  'run: bash ./scripts/ci/check_poco_bft_v0_recovery_smoke.sh'
require_literal "$POCO_WORKFLOW" \
  'run: bash ./scripts/ci/check_poco_bft_v0_ci_truth.sh'
require_literal "$RECOVERY_GATE" 'require_one_executed_test() {'
require_literal_count "$RECOVERY_GATE" \
  'grep -Fc -- "$filter: test"' 4
require_literal_count "$RECOVERY_GATE" \
  'test result: ok. 1 passed; 0 failed; 0 ignored;' 1
require_literal "$RECOVERY_GATE" \
  'torn_halt_latch_is_fail_closed_without_damaging_the_head_slots'
require_literal "$RECOVERY_GATE" \
  'deleting_persistent_wal_or_shm_after_close_fails_reopen_closed'
require_literal "$RECOVERY_GATE" \
  'tampered_only_valid_lock_watermark_slot_is_rejected_on_reopen'
require_literal "$RECOVERY_GATE" \
  'callback_persistence_preserves_exact_sign_intent_across_crash_resume'
require_literal "$RECOVERY_GATE" \
  'synced_callback_persistence_preserves_exact_vote_intent_across_crash_resume'
require_literal "$RECOVERY_GATE" \
  'external_watermark_recovers_each_local_first_commit_window'
require_literal "$RECOVERY_GATE" \
  'whole_namespace_rollback_is_detected_by_external_watermark'
require_literal "$RECOVERY_GATE" \
  'bounded_timeout_signing_persists_before_broadcast_and_replays_exactly'
require_literal "$RECOVERY_GATE" \
  'unavailable_producer_leaves_exact_prepared_tail_for_same_intent_retry'
require_literal "$RECOVERY_GATE" \
  'signer_revision_ahead_of_authenticated_safety_head_fails_startup'
require_literal "$RECOVERY_GATE" \
  'proposal_obligation_recovery_rebuilds_the_exact_target_before_invalid_callback'
require_literal "$RECOVERY_GATE" \
  'synced_obligation_recovery_rebuilds_the_exact_route_and_witness'
require_literal "$RECOVERY_GATE" \
  'obligation_recovery_rejects_tampered_duplicate_and_concurrent_records'
reject_literal "$RECOVERY_GATE" \
  'run_feature_unit_filter trnm-poco-node recovery-test-support'
reject_literal "$RECOVERY_GATE" \
  'real_process_sigkill_matrix_recovers_o_p_o_d_c_d_and_c_k'
require_literal "$RECOVERY_GATE" \
  'run_feature_integration_filter trnm-poco-node recovery-process-test-support \
  timeout_signing_process_kill_matrix \
  real_process_sigkill_matrix_replays_exact_bounded_timeout_signing'
require_literal "$RECOVERY_GATE" \
  'if [[ "${TRNM_RUN_LEGACY_APP_ARCHIVE_TESTS:-0}" == "1" ]]; then'
require_literal "$RECOVERY_GATE" \
  'poco_bft_recovery_evidence_mode=LEGACY_APP_ARCHIVE_OPT_IN'
require_literal "$RECOVERY_GATE" \
  'LEGACY_APP_MANIFEST="$ROOT/trillionnium/crates/trnm-consensus-app/Cargo.toml"'
require_literal "$RECOVERY_GATE" \
  'if [[ "$package" == "trnm-consensus-app" ]]; then'
require_literal "$RECOVERY_GATE" \
  'manifest="$LEGACY_APP_MANIFEST"'
require_literal_count "$RECOVERY_GATE" \
  'cargo test --manifest-path "$manifest" --locked \' 2
require_literal "$RECOVERY_GATE" \
  'validation_recovery_process_kill_matrix=UNAVAILABLE_NON_BUILDABLE_ARCHIVE_SOURCE'
require_literal "$RECOVERY_GATE" \
  'validation_recovery_process_kill_scope=none'
require_literal "$RECOVERY_GATE" \
  'validation_recovery_process_kill_checkpoint_count=0'
require_literal "$RECOVERY_GATE" \
  'validation_recovery_process_kill_checkpoint_origin=none'
require_literal_count "$RECOVERY_GATE" \
  'bounded_timeout_process_sigkill_matrix=EVALUATED_ACTIVE_NATIVE' 2
require_literal "$RECOVERY_GATE" \
  'legacy_app_archive_tests=EVALUATED_STANDALONE_ARCHIVE_NOT_ACTIVE_NATIVE_EVIDENCE'
require_literal "$RECOVERY_GATE" \
  'legacy_node_recovery_feature_tests=UNAVAILABLE_NON_BUILDABLE_ARCHIVE_SOURCE'
require_literal "$RECOVERY_GATE" \
  'legacy_process_sigkill_feature_tests=UNAVAILABLE_NON_BUILDABLE_ARCHIVE_SOURCE'
require_literal "$RECOVERY_GATE" \
  'legacy_app_archive_tests=SKIPPED_NO_ACTIVE_NATIVE_WORKFLOW_AUTHORITY'
require_literal "$RECOVERY_GATE" \
  'legacy_node_recovery_feature_tests=SKIPPED_NO_ACTIVE_NATIVE_WORKFLOW_AUTHORITY'
require_literal "$RECOVERY_GATE" \
  'legacy_process_sigkill_feature_tests=SKIPPED_NO_ACTIVE_NATIVE_WORKFLOW_AUTHORITY'
require_literal "$RECOVERY_GATE" \
  'poco_bft_recovery_evidence_mode=ACTIVE_NATIVE_DEFAULT_ONLY'
reject_literal "$RECOVERY_GATE" \
  'bounded_timeout_process_sigkill_matrix=ARCHIVED_LOCAL_EVIDENCE_NOT_ACTIVE_NATIVE_CI'
require_literal "$RECOVERY_GATE" \
  'poco_bft_recovery_smoke=passed scope=core-sign-safety-journal-torn-halt-latch-wal-shm-watermark-bounded-timeout-signing-replay-active-native-default'
require_literal "$RECOVERY_GATE" 'vote_signing_effect_loop=NOT_IMPLEMENTED'
require_literal "$RECOVERY_GATE" 'power_loss_fsync_matrix=NOT_EVALUATED'
reject_literal "$RECOVERY_GATE" \
  'validation_recovery_process_kill_matrix=NOT_EVALUATED'
reject_literal "$RECOVERY_GATE" \
  "'validation_recovery_process_kill_matrix=SIGKILL_EVALUATED'"
reject_literal "$RECOVERY_GATE" \
  "'bounded_timeout_process_sigkill_matrix=SIGKILL_EVALUATED'"
require_literal "$RECOVERY_GATE" 'valid_recovery=not_implemented'
require_literal "$RECOVERY_GATE" 'unavailable_recovery=not_implemented'

# The G3 Stage0 contract gate is a no-Cargo, no-SSH source/fixture self-test. It
# must bind the strict clean-commit candidate through schema-3 native/aggregate
# reports, current readiness fixtures, and the full Cut/Park/ParkedAck inert
# handoff without accepting historical raw observations as current evidence.
require_literal "$G3_LAN_FLEET_GATE" \
  'poco_g3_current_fleet_observation_self_test=passed producer_positive=1 bounded_memory_positives=3 negatives=25 inventory_alignment_negatives=2 linux_memtotal_tolerance_bytes=32768 linux_page_bytes=4096 macos_memory_exact=true historical_gate=false build=false validator_run=false multihost_run=false geo_wan=false production=false'
require_literal "$G3_LAN_FLEET_GATE" \
  'poco_g3_current_run_readiness_self_test=passed producer_positive=1 negatives=23 historical_gate=false build=false validator_run=false multihost_run=false geo_wan=false production=false'
require_literal "$G3_LAN_FLEET_GATE" \
  'poco_g3_source_candidate_test=passed strict_profile=clean-commit-v1 fresh_clone_byte_identity=true git_tree_blob_binding=true commit_tree_binding=true cargo_lock_bound=true dirty_worktrees_rejected=true legacy_v1_audit_only=true actual_build_executed=false production_activation=false geo_wan=false'
require_literal "$G3_LAN_FLEET_GATE" \
  'poco_g3_reproducible_builder_boundary_test=passed ambient_overrides=12 git_authority_overrides=5 all_cargo_configs_rejected=true closed_build_environment=true cargo_home_and_environment_paths_remapped=true candidate_inode_pinned=true strict_checker_required=true cargo_lock_verified_before_build=true schema3_provenance=true'
require_literal "$G3_LAN_FLEET_GATE" \
  'poco_g3_reproducible_build_report_test=passed strict_candidate=true schema3_provenance=true both_architectures_bound=true legacy_candidate_rejected=true schema2_local_rejected=true'
require_literal "$G3_LAN_FLEET_GATE" \
  'poco_g3_stage0_reproducible_build_evidence_test=passed positives=3 negatives=51 shallow_binary_bytes_rehashed=false deep_binary_bytes_rehashed=true operator_recorded_execution=true cryptographic_execution_attestation=false'
require_literal "$G3_LAN_FLEET_GATE" \
  'poco_g3_stage0_observation_status_test=passed positives=2 negatives=7 structured_incomplete=true require_complete_fail_closed=true contract_self_tests_not_observations=true production_activation_blocked=true report_hash_bound=true cross_time_control_bound=true rust_src_drift_not_reproducible=true committed_v2_remap_control=true committed_clean_tool_boundary_fail_closed=true initial_cache_miss_preserved=true'
require_literal "$G3_LAN_FLEET_GATE" \
  'poco_g3_network_smoke_fleet_test=passed positives=19 negatives=15'
require_literal "$G3_LAN_FLEET_GATE" \
  'poco_g3_run_bundle_self_test=passed positives=3 negatives=58'
require_literal "$G3_LAN_FLEET_GATE" \
  'poco_g3_signed_runtime_evidence_tests=passed positives=1 negatives=27 unsigned_observation_authority=false g3_complete=false'
require_literal "$G3_LAN_FLEET_GATE" \
  'poco_g3_stage0_direct_seven_bundle_v1_test=passed cargo_executed=false fixture_only=true deep_candidate=true cargo_lock_member=true dual_arch_binaries=4 symlink=blocked duplicate_json=blocked trailing=blocked ancestor_dirfd_swap=blocked failure_cleanup=close-only private_quarantine_retained=true foreign_nested_secret=preserved foreign_leaf=preserved fstat_fault_fd_baseline=true linux_renameat2_noreplace=verified unverified_publish=blocked quarantine_rng_alias=blocked unsafe_publish_parent=blocked prepublish_failure_final_absent=true publish_collision_foreign=preserved postrename_failure=indeterminate rename_exception_identity_recheck=true pinned_root_decoy=blocked cryptographic_content_equivalence_binding=true checker_itself_fd_rooted=false path_alias_authority=false binding_extra_directory=blocked binding_identical_inode_swap=blocked binding_fault_fd_baseline=true binding_manifest_16m_plus_one=blocked hostile_same_euid_postbinding=false same_euid_source_swap=indeterminate postrename_inode_match=required successful_publish_inode=preserved successful_quarantine=absent double_slash_disjoint=blocked public_secret_prewrite=blocked oversized_128m_plus_one_prewrite=blocked low_disk_prewrite=blocked tree_entries_4096_plus_one=blocked tree_depth_64_plus_one=blocked stage0_profile_max_file_bytes=134217728 runner_generic_512m_compatibility_claim=false exact_json_integers=blocked manifest_complete=true roles_unique=true failure=blocked cleanup=blocked observer_set=7 replay_sets=7 raw_replay_substitution=blocked raw_replay_hash_chain=blocked terminal_seal_signature=verified terminal_seal_signature_mutation=blocked terminal_agreement=exact proposal_qc_finality_semantics_independently_decoded=false runner_validator_run_completed=false stage0_direct_seven_observed=scoped validator_run_7_completed_observed=true fault_matrix=false performance=false g3_lan=false geo_wan=false production=false'
require_literal "$G3_LAN_FLEET_GATE" \
  'poco_fault_restart_handoff_v1_test=passed target_only=true exit75_exact=true exit75_ssh_preserved=true schema2_exact=true p1_locator_digest_unlink=true peer_liveness=true single_p2_launch=true normal_artifacts_absent=true truth_bits_unchanged=true'
require_literal "$G3_LAN_FLEET_GATE" \
  'poco_g3_lan_fleet_contract_self_test_gate=passed stage0_observation_complete=false observation_status_evaluated=false required_files='
require_literal "$G3_LAN_FLEET_GATE" \
  'readiness=current_fixture_self_tests_only strict_candidate=clean-commit-v1 strict_builder_schema=3 strict_aggregate_schema=3 commit_tree_blob_cargo_lock_bound=true'
require_literal "$G3_LAN_FLEET_GATE" \
  'cargo_executed=false ssh_executed=false evidence_generated=false validator_run=false multihost_observed=false fault_matrix_completed=false performance_evidence=false geo_wan=false production_activation=false strict_clippy_gate_closed=false'
reject_literal "$G3_LAN_FLEET_GATE" \
  'poco_g3_lan_fleet_stage0_gate=passed'
require_literal "$G3_STAGE0_OBSERVATION_STATUS" \
  'DEFAULT_STATUS = ROOT / "docs/evidence/poco-g3/status.toml"'
require_literal "$G3_STAGE0_OBSERVATION_STATUS" \
  '"fresh_clone_fmt_observed"'
require_literal "$G3_STAGE0_OBSERVATION_STATUS" \
  '"fresh_clone_check_observed"'
require_literal "$G3_STAGE0_OBSERVATION_STATUS" \
  '"key_tests_observed"'
require_literal "$G3_STAGE0_OBSERVATION_STATUS" \
  '"validator_run_7_completed"'
require_literal "$G3_STAGE0_OBSERVATION_STATUS" \
  '"--require-complete"'
require_literal "$G3_STAGE0_OBSERVATION_STATUS" \
  'contract_self_tests_are_observations=false'
require_literal "$G3_STAGE0_OBSERVATION_STATUS" \
  'native_reproducible_build='
require_literal "$G3_STAGE0_OBSERVATION_STATUS" \
  'rust_src_cross_time_control_bound=true'
require_literal "$G3_STAGE0_OBSERVATION_STATUS" \
  'rust_src_remap_code_under_test_committed='
require_literal "$G3_STAGE0_OBSERVATION_STATUS" \
  'committed_rust_src_remap_builder_control_observed='
require_literal "$G3_STAGE0_STATUS" \
  'current_rust_src_cross_time_control_profile = "poco-g3-stage0-rust-src-cross-time-control-v3"'
require_literal "$G3_RUST_SRC_CROSS_TIME_REPORT" \
  '"committed_v2_remap_control_observation": {'
if ! g3_stage0_observation_status="$(python3 "$G3_STAGE0_OBSERVATION_STATUS")"; then
  fail "typed G3 Stage0 observation status is invalid"
fi
expected_g3_stage0_observation_status='poco_g3_stage0_observation_status=reported stage0_observation_complete=false native_build_records_present=true within_invocation_binary_identity_observed=true native_reproducible_build=true native_build_cryptographically_attested=false rust_src_cross_time_control_bound=true rust_src_cross_time_control_sha256=a00870446ea027a95786ee567c466b05339359ddd0261b10fc1eac1d4681ae63 rust_src_drift_observed=true rust_src_remap_control_restored_historical_hashes=true rust_src_remap_code_under_test_committed=true committed_rust_src_remap_builder_control_observed=true committed_candidate_rust_src_remap_fix_observed=false rust_src_remap_in_d6bb_candidate=false rust_src_remap_tool_source_bound_to_raw_report=false fresh_clone_report_bound=true fresh_clone_report_sha256=77389a6a70942c8bc076882b27a9c555134a08eb24f0568fcc7a49dde6a89b21 fresh_clone_fmt_observed=true fresh_clone_check_observed=true key_tests_observed=true initial_offline_cache_ready=false public_dependency_fetch_used=true formal_rerun_offline=true fresh_clone_runner_cryptographically_attested=false fresh_clone_logs_bundled=false deep_reverification_bundle_available=false validator_run_7_completed=false contract_self_tests_are_observations=false missing=committed_candidate_rust_src_remap_fix_observed,current_fleet_probe_observed,current_run_readiness_observed,stage0_deep_reverification_bundle_available,validator_run_7_completed'
[[ "$g3_stage0_observation_status" == "$expected_g3_stage0_observation_status" ]] \
  || fail "typed G3 Stage0 observation truth differs from the expected incomplete boundary"
require_literal "$G3_SOURCE_CANDIDATE_PREPARE" \
  'parser.add_argument("--require-clean", action="store_true")'
require_literal "$G3_SOURCE_CANDIDATE_PREPARE" \
  'CARGO_LOCK_PATH = "trillionnium/Cargo.lock"'
require_literal "$G3_SOURCE_CANDIDATE_CHECK" \
  'def validate(path: pathlib.Path, *, require_clean: bool = False)'
require_literal "$G3_SOURCE_CANDIDATE_CHECK" \
  'strict source candidate must use clean-commit-v1'
require_literal "$G3_REPRODUCIBLE_CANDIDATE_BUILD" \
  '[sys.executable, str(CHECK), str(candidate), "--require-clean"]'
require_literal "$G3_REPRODUCIBLE_CANDIDATE_BUILD" \
  '"schema_version": 3'
require_literal "$G3_REPRODUCIBLE_BUILD_REPORT_ASSEMBLER" \
  'check_source_candidate.validate(path, require_clean=True)'
require_literal "$G3_REPRODUCIBLE_BUILD_REPORT_ASSEMBLER" \
  'report.get("schema_version") != 3'
require_literal "$G3_FAULT_RESTART_RUNNER" \
  'PROCESS2_INERT_BOUNDARY_MESSAGE_V1 = ('
require_literal "$G3_FAULT_RESTART_RUNNER" \
  '"continuous consensus RestartCut/RestartPark/RestartParkedAck-joined "'
require_literal "$G3_FAULT_RESTART_RUNNER" \
  '"process2 is inert; authenticated start-catchup, RecoveryReady, and "'
require_literal "$G3_FAULT_RESTART_HANDOFF_TEST" \
  'assert fleet.PROCESS2_INERT_BOUNDARY_MESSAGE_V1 == ('
require_literal "$G3_LAB_CONSENSUS_RUNTIME" \
  'continuous consensus RestartCut/RestartPark/RestartParkedAck-joined process2 is inert; authenticated start-catchup, RecoveryReady, and RecoveryStart remain unavailable'
reject_literal "$G3_LAN_FLEET_GATE" 'docs/evidence/'
reject_literal "$G3_LAN_FLEET_GATE" 'lan-fleet-probe-2026-08-13.json'
reject_literal "$G3_LAN_FLEET_GATE" 'lan-run-readiness-2026-08-13.json'
reject_literal "$G3_LAN_FLEET_GATE" 'positives=2 negatives=23'
reject_literal "$G3_LAN_FLEET_GATE" 'positives=3 negatives=55'
reject_literal "$G3_LAN_FLEET_GATE" 'positives=1 negatives=24'
reject_literal "$G3_LAN_FLEET_GATE" \
  'poco_g3_network_smoke_fleet_test=passed positives=4 negatives=5'
reject_literal "$G3_LAN_FLEET_GATE" 'RestartCut-joined process2'

# G1c is a bounded recovery join, not a relaxation of ordinary Core recovery.
# Keep the implementation/test anchors and exact claim boundary machine-checked.
require_literal "$CORE_SOURCE" \
  'pub fn begin_payload_validation_obligation_recovery_v0<V: SignatureVerifier>('
require_literal "$CORE_TESTS" \
  'fn recovery_with_a_claimed_durable_validation_fails_closed_without_reopening_it()'
require_literal "$CORE_TESTS" \
  'fn proposal_obligation_recovery_rebuilds_the_exact_target_before_invalid_callback()'
require_literal "$CORE_TESTS" \
  'fn obligation_recovery_rejects_tampered_duplicate_and_concurrent_records()'
require_literal "$APP_RECOVERY" 'pub fn open_existing_v8('
require_literal "$APP_RECOVERY" 'NativeValidationRecoveryUnsupportedV0::Reserved'
require_literal "$APP_RECOVERY" 'NativeValidationRecoveryUnsupportedV0::Evaluated'
require_literal "$APP_RECOVERY" 'NativeValidationRecoveryUnsupportedV0::Applied'
require_literal "$APP_RECOVERY" 'NativeValidationRecoveryUnsupportedV0::Valid'
require_literal "$APP_RECOVERY" 'NativeValidationRecoveryUnsupportedV0::Unavailable'
require_literal "$APP_RECOVERY" 'struct NativeValidationRecoveryNamespacePinV0 {'
require_literal "$APP_RECOVERY" 'let mut active_recovery_job_count = 0_usize;'
require_literal "$APP_RECOVERY" \
  'expected_safety_journal_id: [u8; 32],'
require_literal "$APP_RECOVERY" \
  'expected_safety_verifier_profile_ref: [u8; 32],'
require_literal "$APP_RECOVERY" \
  'confirmed: &ConfirmedNativeDeterministicInvalidHeadV0,'
require_literal "$APP_RECOVERY" \
  'bootstrap_native_validation_safety_binding_manifest_v0('
require_literal "$APP_RECOVERY" \
  'open_and_pin_native_validation_safety_binding_manifest_v0('
require_literal "$APP_RECOVERY" 'file_name.push(".safety-binding-v0");'
reject_literal "$APP_RECOVERY" \
  'pub trait NativeValidationConfirmedInvalidTransitionV0'
require_literal "$APP_STORE_SOURCE" 'ApplicationStoreOwnerModeV0::OrdinaryShared => {'
require_literal "$APP_STORE_SOURCE" 'FileExt::try_lock_shared(&lock_handle)'
require_literal "$APP_STORE_SOURCE" 'ApplicationStoreOwnerModeV0::RecoveryExclusive => {'
require_literal "$APP_STORE_SOURCE" 'FileExt::try_lock_exclusive(&lock_handle)'
require_literal "$APP_STORE_SOURCE" \
  'pub(super) fn validate_secure_native_validation_recovery_namespace_v0('
require_literal "$SAFETY_STORE_SOURCE" \
  'pub struct ConfirmedNativeDeterministicInvalidHeadV0 {'
require_literal "$SAFETY_STORE_SOURCE" \
  'pub fn confirmed_native_deterministic_invalid_head_v0('
require_literal "$SAFETY_STORE_SOURCE" 'pub const fn journal_id_v0(&self) -> [u8; 32] {'
require_literal "$SAFETY_STORE_SOURCE" \
  'pub const fn verifier_profile_ref_v0(&self) -> [u8; 32] {'
reject_literal "$SAFETY_STORE_SOURCE" \
  'impl NativeValidationConfirmedInvalidTransitionV0 for ConfirmedNativeDeterministicInvalidHeadV0'
reject_literal "$NODE_SOURCE" 'NativeValidationConfirmedInvalidTransitionV0'
reject_literal "$NODE_SOURCE" 'struct ConfirmedNativeInvalidSafetyHeadV0 {'
require_literal "$NODE_SOURCE" \
  'safety_store.journal_id_v0(),'
require_literal "$NODE_SOURCE" \
  'safety_store.verifier_profile_ref_v0(),'
require_literal "$NODE_SOURCE" \
  'left.starts_with(right) || right.starts_with(left)'
require_literal "$NODE_RECOVERY_TESTS" \
  'fn strict_three_store_recovery_matrix_closes_o_p_o_d_c_d_and_c_k()'
require_literal "$NODE_CARGO" 'recovery-process-test-support = ['
require_literal "$NODE_CARGO" '  "dep:ed25519-dalek",'
require_literal "$NODE_CARGO" '  "dep:fs2",'
reject_literal "$NODE_CARGO" '  "recovery-test-support",'
reject_literal "$NODE_CARGO" 'name = "trnm-poco-recovery-kill-helper"'
require_literal "$NODE_CARGO" 'name = "trnm-poco-timeout-signing-kill-helper"'
reject_literal "$NODE_CARGO" 'name = "recovery_process_kill_matrix"'
require_literal "$NODE_CARGO" 'name = "timeout_signing_process_kill_matrix"'
require_toml_target_feature "$NODE_CARGO" bin \
  trnm-poco-timeout-signing-kill-helper recovery-process-test-support
require_toml_target_feature "$NODE_CARGO" test \
  timeout_signing_process_kill_matrix recovery-process-test-support
require_literal "$NODE_PROCESS_KILL_TEST" \
  'fn real_process_sigkill_matrix_recovers_o_p_o_d_c_d_and_c_k()'
require_literal "$NODE_PROCESS_KILL_TEST" 'ExitStatusExt'
require_literal "$NODE_PROCESS_KILL_TEST" 'SIGKILL'
require_literal "$NODE_PROCESS_KILL_TEST" \
  'let exact_identity = checkpoint'
require_literal "$NODE_PROCESS_KILL_TEST" \
  'format!("verified_v0={route}/{reason}/completion_acked;{exact_identity}\n")'
require_literal "$NODE_PROCESS_KILL_HELPER" \
  'open_existing_with_process_checkpoint_observer_v0'
require_literal "$NODE_PROCESS_KILL_HELPER" \
  'identity_v0={}:{}:{};completion_revision={};watermark_v0={}:{}:{}:{}'
require_literal "$NODE_TIMEOUT_PROCESS_KILL_TEST" \
  'fn real_process_sigkill_matrix_replays_exact_bounded_timeout_signing()'
require_literal "$NODE_TIMEOUT_PROCESS_KILL_TEST" 'EXPECTED_PHASES.len(), 6'
require_literal "$NODE_TIMEOUT_PROCESS_KILL_TEST" 'status.signal()'
require_literal "$NODE_TIMEOUT_PROCESS_KILL_TEST" 'Some(SIGKILL)'
require_literal "$NODE_TIMEOUT_PROCESS_KILL_HELPER" \
  'PocoNodeHostV0::open_existing('
require_literal "$NODE_TIMEOUT_PROCESS_KILL_HELPER" \
  'host.on_local_timeout_with_process_checkpoint_observer_v0'
require_literal "$NODE_TIMEOUT_PROCESS_KILL_HELPER" \
  'ProducerEnteredAfterIntentWatermark'
require_literal "$NODE_TIMEOUT_PROCESS_KILL_HELPER" \
  'ProducerGeneratedBeforeReturn'
require_literal "$NODE_TIMEOUT_PROCESS_KILL_HELPER" \
  '.verify(validator_set, &StrictEd25519Verifier)'
require_literal "$POCO_WORKFLOW" \
  "-name '*trnm-poco-timeout-signing-kill-helper*' -print -quit"
require_literal "$POCO_WORKFLOW" \
  'development-only library archive unexpectedly contains the timeout SIGKILL helper'
require_literal "$NODE_SOURCE" '"obligation_callback_pending"'
require_literal "$NODE_SOURCE" '"obligation_delivered"'
require_literal "$NODE_SOURCE" '"completion_delivered"'
require_literal "$NODE_SOURCE" '"completion_acked"'
require_literal "$NODE_PROCESS_WATERMARK" \
  'It is not an independently administered'
require_literal "$NODE_PROCESS_WATERMARK" \
  'cloning, hostile same-EUID replacement, device write-cache loss, or power'
require_literal "$NODE_PROCESS_WATERMARK" \
  'fn file_watermark_excludes_live_owner_and_enforces_exact_cas()'
require_literal "$NODE_PROCESS_WATERMARK" \
  'fn file_watermark_rejects_checksum_corruption_and_trailing_bytes()'
require_literal "$NODE_CARGO" 'production_candidate = false'
require_literal "$NODE_CARGO" 'production_consensus_activation = false'
require_literal "$NODE_CARGO" 'incomplete = true'
require_literal "$NODE_CARGO" 'effect_driver = false'
require_literal "$NODE_CARGO" 'bounded_timeout_signing_effect_loop = true'
require_literal "$NODE_CARGO" 'vote_signing_effect_loop = false'
require_literal "$NODE_CARGO" 'production_signature_producer = false'
require_literal "$NODE_SOURCE" 'pub const PRODUCTION_CANDIDATE_V0: bool = false;'
require_literal "$NODE_SOURCE" \
  'pub const HOST_IMPLEMENTATION_COMPLETE_V0: bool = false;'
require_literal "$NODE_TIMEOUT_SOURCE" 'pub fn on_local_timeout_v0('
require_literal "$NODE_TIMEOUT_SOURCE" \
  'pub fn on_local_timeout_with_process_checkpoint_observer_v0<F>('
require_literal "$NODE_TIMEOUT_SOURCE" \
  'PocoNodeTimeoutSigningProcessCheckpointPhaseV0::SafetyPersistedBeforeStorageAck'
require_literal "$NODE_TIMEOUT_SOURCE" \
  'PocoNodeTimeoutSigningProcessCheckpointPhaseV0::SignatureRequestedBeforeJournal'
require_literal "$NODE_TIMEOUT_SOURCE" \
  'PocoNodeTimeoutSigningProcessCheckpointPhaseV0::SignaturePersistedBeforeSignatureReady'
require_literal "$NODE_TIMEOUT_SOURCE" \
  'PocoNodeTimeoutSigningProcessCheckpointPhaseV0::BroadcastProducedBeforeReturn'
require_literal "$NODE_TIMEOUT_SOURCE" '.sign_exact_v0(&intent, &mut self.signature_producer)'
require_literal "$NODE_TIMEOUT_SOURCE" 'pub struct PocoNodeSignedOutboundV0'
require_literal "$NODE_TIMEOUT_SOURCE" \
  'PocoNodeHostErrorV0::UnsupportedTimeoutSigningIntentKind'
require_literal "$NODE_TIMEOUT_SOURCE" \
  'runtime_status: BoundedTimeoutRuntimeStatusV0'
require_literal "$NODE_TIMEOUT_SOURCE" \
  'PocoNodeHostErrorV0::BoundedTimeoutHostFailStopped'
require_literal "$NODE_TIMEOUT_SOURCE" \
  'SignatureProducerErrorV0::Unavailable'
require_literal "$NODE_TIMEOUT_SOURCE" \
  'source: ExternalWatermarkErrorV0::Unavailable'
require_literal "$NODE_SOURCE" \
  'fn bounded_timeout_signing_persists_before_broadcast_and_replays_exactly()'
require_literal "$NODE_SOURCE" \
  'fn unavailable_producer_leaves_exact_prepared_tail_for_same_intent_retry()'
require_literal "$NODE_SOURCE" \
  'fn signer_revision_ahead_of_authenticated_safety_head_fails_startup()'
require_literal "$NODE_SOURCE" \
  'fn non_retryable_signer_failure_terminally_fail_stops_the_live_host()'
require_literal "$G1C_TRUTH" \
  'the admitted matrix is `O+P`, `O+D`, `C+D`, and `C+K`'
require_literal "$G1C_TRUTH" \
  'G1e validation-recovery SIGKILL is archive-only.'
require_literal "$RELEASE_TRUTH" \
  'G1e validation-recovery SIGKILL is archive-only.'
require_literal "$ROOT_README" \
  'G1e validation-recovery SIGKILL is archive-only.'
require_literal "$PROTOCOL_README" \
  'G1e validation-recovery SIGKILL is archive-only.'
require_literal "$INVARIANTS_DOC" \
  'G1e validation-recovery SIGKILL is archive-only.'
require_literal "$DELIVERY_PLAN" \
  'G1e validation-recovery SIGKILL is archive-only.'
require_literal "$DUAL_TRACK_DECISION" \
  'G1e validation-recovery SIGKILL is archive-only.'
require_literal "$INVARIANTS_DOC" \
  'the active G1e checkpoint count is zero'
require_literal "$PROTOCOL_README" \
  'only to the separate six-point bounded-timeout G1f helper and matrix'
require_literal "$CONSENSUS_SAFETY_DOC" \
  'including an `fsync`-equivalent for both data and metadata needed after power loss'
require_literal "$PRODUCTION_CONTRACTS" '## Required crash matrix'
require_literal "$PRODUCTION_CONTRACTS" \
  'signer-journal fsync, signature production,'

# G1f is one default-build timeout lane, not a production/general driver.
require_literal "$ROOT_README" \
  'G1f ordinary owner now uniquely holds Core, SafetyStore, signer journal, and'
require_literal "$RELEASE_TRUTH" \
  'default-build G1f path is bounded to a host-derived local timeout'
require_literal "$G1C_TRUTH" \
  'G1f adds a distinct default-build ordinary owner for one bounded local-timeout'
require_literal "$PROTOCOL_README" \
  'The distinct G1f ordinary owner is active but deliberately bounded.'
require_literal "$INVARIANTS_DOC" \
  '- the distinct G1f ordinary host MUST own one Core, SafetyStore, signer journal,'
require_literal "$DELIVERY_PLAN" \
  'G1f now provides the first default-build ordinary vertical effect loop.'
require_literal "$DUAL_TRACK_DECISION" \
  'G1f separately advances steps 2 and 3 without claiming either complete.'
require_literal "$PRODUCTION_CONTRACTS" \
  'Current G1f evidence closes only the local-timeout subset of this contract.'
require_literal "$ROOT_README" \
  'required-feature local Linux matrix now kills and reaps a direct child with'
require_literal "$RELEASE_TRUTH" \
  'required-feature local Linux process matrix covers six'
require_literal "$G1C_TRUTH" \
  'required-feature local Linux matrix now exercises six real child-process'
require_literal "$PROTOCOL_README" \
  'required-feature timeout matrix now covers six real local Linux child-process'
require_literal "$INVARIANTS_DOC" \
  '- the required-feature G1f process matrix MUST cover exactly six distinct'
require_literal "$DELIVERY_PLAN" \
  'matrix now covers six exact child SIGKILL/reap boundaries from SafetyStore'
require_literal "$DUAL_TRACK_DECISION" \
  'child SIGKILL/reap and two-fresh-process exact replay at six bounded points'
require_literal "$PRODUCTION_CONTRACTS" \
  'local Linux matrix now covers six direct-child SIGKILL/reap boundaries from'
require_literal "$PROTOCOL_README" \
  'A non-retryable runtime failure terminally latches'
require_literal "$INVARIANTS_DOC" \
  'latch the live G1f host until a fresh authenticated reopen.'
reject_literal "$ROOT_README" 'G1f production node'
reject_literal "$RELEASE_TRUTH" 'G1f production signer'
reject_literal "$RELEASE_TRUTH" 'no real-process SIGKILL or power-loss'
reject_literal "$G1C_TRUTH" 'real-process SIGKILL and power-loss matrices are not evaluated'
reject_literal "$PROTOCOL_README" 'timeout-path SIGKILL and power-loss matrices remain unevaluated'

# Keep the ordinary recovery rejection distinct from the one-obligation G1c
# session, and describe the concrete Safety token as bounded joint provenance
# rather than either standalone authority or comparison-only data.
require_literal "$ROOT_README" \
  'The G1c validation-recovery slice is intentionally narrow. Ordinary'
require_literal "$ROOT_README" \
  'grants no callback, Core, or general application transition authority by'
require_literal "$PROTOCOL_README" \
  'Ordinary `Core::recover` validates every schema-v8 obligation and inert'
require_literal "$PROTOCOL_README" \
  'The token is not standalone or general transition authority.'
require_literal "$WIRE_DOC" \
  'Ordinary `Core::recover` validates schema-v8 obligations and inert completions'
require_literal "$INVARIANTS_DOC" \
  '- ordinary `Core::recover` MUST validate every schema-v8 obligation and inert'
require_literal "$INVARIANTS_DOC" \
  'capability MUST NOT implement an authority trait or authorize any callback,'
require_literal "$DELIVERY_PLAN" \
  'recovery session is the only bounded authenticated-ticket exception and'
require_literal "$G1C_TRUTH" \
  'native-invalid exact-readback token grants no detached or general'
reject_literal "$PROTOCOL_README" \
  'Recovery validates every schema-v8 obligation and inert completion and then rejects'
reject_literal "$WIRE_DOC" \
  'Recovery validates schema-v8 obligations and inert completions and then rejects'
reject_literal "$INVARIANTS_DOC" \
  '- recovery MUST validate every schema-v8 obligation and inert completion and then'
reject_literal "$DELIVERY_PLAN" \
  'of a pending SignIntent across unrelated callback persistence. Recovery first'
reject_literal "$ROOT_README" \
  'grants no public callback, Core, or application transition authority'
reject_literal "$G1C_TRUTH" 'grants only authenticated comparison facts'

# The fail-closed node scaffold must compile and lint wherever its source can
# trigger this workflow, while remaining explicitly incomplete and outside the
# uploaded library archive.
require_literal "$POCO_WORKFLOW" \
  'cargo test --locked -p trnm-poco-node --all-targets --features recovery-process-test-support'
require_literal "$POCO_WORKFLOW" \
  'cargo clippy --locked -p trnm-poco-node --all-targets --features recovery-process-test-support --no-deps -- -D warnings'
require_literal_count "$POCO_WORKFLOW" '--features recovery-process-test-support' 2
require_literal "$POCO_WORKFLOW" \
  '            -p trnm-poco-node \'
require_literal "$POCO_WORKFLOW" \
  'name: Active native bounded-timeout SIGKILL recovery gate'
reject_literal "$POCO_WORKFLOW" \
  'name: Bounded G1e and G1f real-process SIGKILL recovery gates'
reject_literal "$POCO_WORKFLOW" \
  'cargo test --locked -p trnm-consensus-app --lib'
reject_literal "$POCO_WORKFLOW" \
  'cargo clippy --locked -p trnm-consensus-app'
reject_literal "$POCO_WORKFLOW" \
  '            -p trnm-consensus-app \'

# Release-profile libraries are useful integration artifacts, not a node or a
# production-readiness decision. Keep that boundary machine-readable both in
# the workflow UI and in the uploaded archive metadata.
require_literal "$POCO_WORKFLOW" \
  'name: Development-only integration library artifact build'
require_literal "$POCO_WORKFLOW" 'needs: [rust, vectors-schema-proto]'
require_literal "$POCO_WORKFLOW" \
  'cargo build --locked --release --no-default-features \'
require_literal "$POCO_WORKFLOW" \
  'name: trnm-poco-bft-v0-development-libs-${{ github.run_id }}-${{ github.run_attempt }}'
require_literal "$POCO_WORKFLOW" 'artifact_class=development_only'
require_literal "$POCO_WORKFLOW" 'build_profile=release'
require_literal "$POCO_WORKFLOW" 'development_only=true'
require_literal "$POCO_WORKFLOW" 'production_consensus_activation=false'
require_literal "$POCO_WORKFLOW" 'deployable_node=false'
require_literal "$POCO_WORKFLOW" 'production_candidate=false'
require_literal "$POCO_WORKFLOW" 'incomplete=true'
require_literal "$POCO_WORKFLOW" 'effect_driver=false'
require_literal "$POCO_WORKFLOW" 'source_bounded_timeout_signing_effect_loop=true'
require_literal "$POCO_WORKFLOW" 'artifact_bounded_timeout_signing_effect_loop=false'
require_literal "$POCO_WORKFLOW" 'source_vote_signing_effect_loop=false'
require_literal "$POCO_WORKFLOW" 'production_signature_producer=false'
require_literal "$POCO_WORKFLOW" 'network_broadcast_transport=false'
require_literal "$POCO_WORKFLOW" 'poco_node_binary_included=false'
require_literal "$POCO_WORKFLOW" 'production_ready=false'
require_literal "$POCO_WORKFLOW" 'test_features_included=false'
require_literal "$POCO_WORKFLOW" 'recovery_test_support_included=false'
require_literal "$POCO_WORKFLOW" 'recovery_process_test_support_included=false'
require_literal "$POCO_WORKFLOW" 'recovery_only_core_step=false'
require_literal "$POCO_WORKFLOW" \
  'source_bounded_timeout_process_sigkill_matrix=EVALUATED'
require_literal "$POCO_WORKFLOW" \
  'source_bounded_timeout_process_sigkill_scope=local_linux_test_only_safety_ack_signer_journal_producer_signature_ready_broadcast'
require_literal "$POCO_WORKFLOW" \
  'source_bounded_timeout_process_sigkill_case_count=6'
require_literal "$POCO_WORKFLOW" \
  'source_bounded_timeout_process_sigkill_checkpoint_origin=official_host_four_boundaries_feature_producer_two_boundaries'
require_literal "$POCO_WORKFLOW" \
  'source_bounded_timeout_process_sigkill_evidence=true'
require_literal "$POCO_WORKFLOW" \
  'artifact_bounded_timeout_process_sigkill_capability=false'
require_literal "$POCO_WORKFLOW" \
  'validation_recovery_scope=deterministic_invalid_existing_only_v0'
require_literal "$POCO_WORKFLOW" \
  'source_validation_recovery_process_sigkill_matrix=UNAVAILABLE_NON_BUILDABLE_ARCHIVE_SOURCE'
require_literal "$POCO_WORKFLOW" \
  'source_validation_recovery_process_sigkill_scope=none'
require_literal "$POCO_WORKFLOW" \
  'source_validation_recovery_process_sigkill_case_count=0'
require_literal "$POCO_WORKFLOW" \
  'source_validation_recovery_process_sigkill_checkpoint_origin=none'
require_literal "$POCO_WORKFLOW" \
  'source_validation_recovery_process_sigkill_evidence=false'
require_literal "$POCO_WORKFLOW" \
  'artifact_validation_recovery_process_sigkill_capability=false'
reject_literal "$POCO_WORKFLOW" \
  'source_validation_recovery_process_sigkill_matrix=EVALUATED'
reject_literal "$POCO_WORKFLOW" \
  'source_validation_recovery_process_sigkill_case_count=16'
reject_literal "$POCO_WORKFLOW" \
  'source_validation_recovery_process_sigkill_evidence=true'
require_literal "$POCO_WORKFLOW" 'process_sigkill_helper_included=false'
require_literal "$POCO_WORKFLOW" 'power_loss_fsync_matrix=NOT_EVALUATED'
require_literal "$POCO_WORKFLOW" 'application_safety_binding_manifest=true'
require_literal "$POCO_WORKFLOW" \
  'application_safety_binding_initializer=fixture_only_not_in_artifact'
require_literal "$POCO_WORKFLOW" 'application_recovery_secure_namespace=true'
require_literal "$POCO_WORKFLOW" \
  'application_recovery_secure_namespace_scope=local_linux_non_same_euid_v0'
require_literal "$POCO_WORKFLOW" 'application_recovery_sqlite_main_fd_identity=false'
require_literal "$POCO_WORKFLOW" 'application_recovery_wal_shm_inode_pinning=false'
require_literal "$POCO_WORKFLOW" 'block_id_speculative_overlay=false'
require_literal "$POCO_WORKFLOW" 'ordered_finalization_queue=false'
require_literal "$POCO_WORKFLOW" 'whole_node_namespace_rollback_protection=false'
require_literal "$POCO_WORKFLOW" 'includes_trnm_consensus_safety_store=true'
require_literal "$POCO_WORKFLOW" 'includes_trnm_consensus_signer_journal=true'
require_literal "$POCO_WORKFLOW" 'external_monotonic_signer_watermark_bound=false'
require_literal "$POCO_WORKFLOW" \
  '${{ runner.temp }}/trnm-poco-bft-v0-development-libs.metadata.txt'
require_literal "$POCO_WORKFLOW" \
  'name: Verify development-only artifact boundary'
reject_literal "$POCO_WORKFLOW" 'name: Release library artifact build'
reject_literal "$POCO_WORKFLOW" \
  'name: trnm-poco-bft-v0-libs-${{ github.run_id }}-${{ github.run_attempt }}'

# The retained Rust-L1 script executes the legacy simulator and loopback
# devnet. A pass is only a development rehearsal pass; it must never emit a
# PoCO, public-testnet, or production GO decision.
require_literal "$LEGACY_WORKFLOW" 'name: legacy-local-harness-preflight'
require_literal "$LEGACY_WORKFLOW" \
  'name: Legacy local harness rehearsal (development only)'
require_literal "$LEGACY_WORKFLOW" \
  'name: legacy-local-harness-preflight-${{ github.run_id }}'
require_literal "$LEGACY_WORKFLOW" 'name: Record non-readiness boundary'
require_literal "$LEGACY_WORKFLOW" \
  'poco_bft_readiness=NOT_EVALUATED'
require_literal "$LEGACY_WORKFLOW" \
  'public_testnet_readiness=NOT_EVALUATED'
require_literal "$LEGACY_WORKFLOW" 'production_ready=false'
require_literal "$LEGACY_PREFLIGHT" 'trnm_legacy_local_harness_preflight'
require_literal "$LEGACY_PREFLIGHT" \
  'evaluation_scope=legacy_local_harness_rehearsal'
require_literal "$LEGACY_PREFLIGHT" 'pass_semantics=local_rehearsal_only'
require_literal "$LEGACY_PREFLIGHT" 'readiness_decision=NOT_EVALUATED'
require_literal "$LEGACY_PREFLIGHT" 'development_only=true'
require_literal "$LEGACY_PREFLIGHT" 'legacy_harness=true'
require_literal "$LEGACY_PREFLIGHT" 'poco_bft_evaluated=false'
require_literal "$LEGACY_PREFLIGHT" 'poco_bft_readiness=NOT_EVALUATED'
require_literal "$LEGACY_PREFLIGHT" 'public_testnet_evaluated=false'
require_literal "$LEGACY_PREFLIGHT" 'public_testnet_readiness=NOT_EVALUATED'
require_literal "$LEGACY_PREFLIGHT" 'production_ready=false'
require_literal "$LEGACY_PREFLIGHT" \
  'truth_source=$GIT_TOPLEVEL/RELEASE_READINESS.md'
require_literal "$LEGACY_PREFLIGHT" 'status=PASS'
require_literal "$LEGACY_PREFLIGHT" 'result=PASS'
reject_literal "$LEGACY_PREFLIGHT" 'status=GO'
reject_literal "$LEGACY_PREFLIGHT" 'result=GO'
reject_literal "$LEGACY_PREFLIGHT" '[OK] testnet preflight passed'
reject_literal "$LEGACY_PREFLIGHT" \
  'truth_source=$ROOT/RELEASE_READINESS.md'

printf '%s\n' \
  'poco_bft_ci_truth=passed safety_store=triggered,tested,clippy,recovery,artifact signer_journal=triggered,tested,clippy,recovery,artifact,incomplete bounded_timeout_signing=default_build_tested,exact_replay timeout_path_sigkill=active_native_exact_one node_scaffold=triggered,tested,clippy,release-built,incomplete validation_recovery_sigkill=unavailable_non_buildable_archive_source power_loss_fsync=not_evaluated legacy_recovery_helper_target=false g3_stage0_contract=tracked,index-bound,no-cargo,current-fixtures-only,clean-commit-v1,schema3,parked-triple-inert g3_stage0_observation=unsigned-build-records,fresh-clone-gates,rust-src-cross-time-drift,committed-v2-remap-control,native-linux-cross-time-reproducible,candidate-remap-fix-absent,incomplete readiness=development_only,no_legacy_go'
