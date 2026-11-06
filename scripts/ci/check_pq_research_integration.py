#!/usr/bin/env python3
"""Fail-closed exact-byte checker for a RESEARCH-only PQ merge.

This checks source identity and false activation flags. It does not execute
cryptography, verify PoN security, or establish production qualification.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import stat
import sys
import tomllib

REL_MANIFEST = "config/pon/pq-cross-branch-corpus-v1.json"
REQUIRED_UPSTREAM = frozenset(("base", "cell", "migration", "witness", "roster", "parity"))
REQUIRED_FALSE = frozenset((
    "production_activation", "independent_accepted", "native_pq_node_integrated",
    "quantum_pon_hardness_qualified", "physical_rollback_resistant",
    "hepta_final_use_integrated", "public_wan_accepted", "allow_legacy_fallback",
))

# Enumerate research implementation entrypoints, not just manually listed pins.
# This prevents a new PQ verifier from being silently omitted from the
# source-integrity manifest. This is NOT proof of cryptographic acceptance.
PQ_SOURCE_DIRS = (
    "formal/pon-nakamoto-v1",
    "trillionnium/crates/trnm-protocol/src",
    "trillionnium/crates/trnm-crypto-primitives/src",
    "trillionnium/crates/trnm-crypto-primitives/tests",
    "trillionnium/crates/trnm-crypto-primitives/examples",
    "trillionnium/crates/trnm-data-availability/src",
    "trillionnium/crates/trnm-data-availability/tests",
    "trillionnium/crates/trnm-mvcc-fee/src",
    "trillionnium/crates/trnm-mvcc-fee/tests",
    "trillionnium/crates/trnm-pon-node/src",
    "trillionnium/crates/trnm-pon-node/tests",
    "trillionnium/crates/trnm-research-protocol/src",
    "trillionnium/crates/trnm-research-protocol/tests",
    # This crate currently keeps tests under src; scan the existing crate root
    # so later integration tests cannot bypass coverage or require a fake dir.
    "trillionnium/crates/trnm-service-settlement",
    # Release roles now perform real ML-DSA verification. Include the entire
    # small crate so nested role/rotation controls cannot escape source pins.
    "trillionnium/crates/trnm-release-bundle",
    "trillionnium/crates/trnm-checkpoint-store",
)

# Every implementation file in these dedicated security owners participates in
# the boundary, including recovery helpers without a PQ-prefixed filename.
COMPLETE_OWNER_SOURCE_DIRS = frozenset((
    "trillionnium/crates/trnm-release-bundle",
    "trillionnium/crates/trnm-checkpoint-store",
))

# This is a newly reconstructed source contract. The old, lost checker bytes
# are not recreated by claiming their historical Git object identity. The
# transport slice remains mandatory and separately bounded from whole-chain PQ.
NATIVE_REQUIRED_PATHS = frozenset((
    "trillionnium/crates/trnm-protocol/src/crypto_profile.rs",
    "trillionnium/crates/trnm-protocol/src/crypto_profile/tests.rs",
    "trillionnium/crates/trnm-protocol/src/pq_legacy_profile.rs",
    "trillionnium/crates/trnm-crypto-primitives/src/pq_candidate.rs",
    "trillionnium/crates/trnm-crypto-primitives/src/pq_profile_auth.rs",
    "trillionnium/crates/trnm-crypto-primitives/examples/pq_parameter_bench.rs",
    "trillionnium/crates/trnm-crypto-primitives/examples/pq_profile_bench.rs",
    "scripts/ci/check_cpq1_parameter_observation.py",
    "scripts/ci/test_cpq1_parameter_observation.py",
    "docs/security/CRYPTO_PROFILE_V1_20261104.md",
    "evidence/crypto-profile-20261104/recompute_benchmark.py",
    "evidence/crypto-profile-20261104/recompute_profile_ids.py",
    ".github/workflows/pon-pq-system-continuation.yml",
    "config/pon/pq-system-required-tests-v1.json",
    "scripts/ci/record_pq_native_command.py",
    "scripts/ci/test_record_pq_native_command.py",
    "docs/security/PQ_NETWORK_DURABLE_WITNESS_V1.md",
    "docs/security/PQ_SYSTEM_CONTINUATION_20261101.md",
    "trillionnium/crates/trnm-pon-node/src/ingress/pq_network/live_admission_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/pq_rollback_witness.rs",
    "trillionnium/crates/trnm-pon-node/src/pq_rollback_witness/tests.rs",
    "trillionnium/crates/trnm-pon-node/src/store/pq_rollback_witness.rs",
    "trillionnium/crates/trnm-pon-node/src/store/pq_rollback_witness/tests.rs",
    "docs/security/PQ_NATIVE_NETWORK_OWNER_V1.md",
    "docs/security/PQ_NATIVE_NETWORK_OWNER_V2.md",
    "docs/security/PQ_APPLICATION_AUTHORIZATION_V6.md",
    "docs/security/PQ_CONTINUOUS_STARTUP_V3.md",
    "trillionnium/crates/trnm-pon-node/Cargo.toml",
    "trillionnium/crates/trnm-pon-node/src/lib.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/public_v2.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/pq_network.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tests.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls_profile.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/context.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/io.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/fixtures.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/tests.rs",
    "trillionnium/crates/trnm-pon-node/src/pq_tls_cli.rs",
    "trillionnium/crates/trnm-pon-node/tests/pq_tls_cli.rs",
    "trillionnium/crates/trnm-pon-node/tests/pq_tls_feature_gate.rs",
    "trillionnium/crates/trnm-pon-node/src/pq_tls_cli_witness.rs",
    "trillionnium/crates/trnm-pon-node/tests/pq_tls_witness_cli.rs",
    "trillionnium/crates/trnm-pon-node/tests/pq_tls_witness_cli/support.rs",
    "config/pon/pq-native-tls-witness-required-tests-v1.json",
    "docs/security/PQ_TLS_WITNESS_CLI_V2.md",
    "config/pon/pq-native-tls-required-tests-v1.json",
    "docs/security/NATIVE_PQ_TLS_LOOPBACK_V1.md",
    "trillionnium/crates/trnm-pon-node/src/ingress/pq_network/canonical_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/history_import.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/history_import_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/public_v3/pq_identity.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/public_v3/pq_identity_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs",
    "trillionnium/crates/trnm-pon-node/src/ancestry_index.rs",
    "trillionnium/crates/trnm-pon-node/src/authenticated_state_archive.rs",
    "trillionnium/crates/trnm-pon-node/src/authenticated_state_archive_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/peer_polling.rs",
    "trillionnium/crates/trnm-pon-node/src/pq_application_v6.rs",
    "trillionnium/crates/trnm-pon-node/src/operator_pq_auth.rs",
    "trillionnium/crates/trnm-pon-node/src/operator_pq_auth_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/operator_pq_startup.rs",
    "trillionnium/crates/trnm-pon-node/src/operator_pq_startup_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/operator_continuous_history.rs",
    "trillionnium/crates/trnm-pon-node/src/operator_continuous_policy.rs",
    "trillionnium/crates/trnm-pon-node/src/operator_continuous_recipient.rs",
    "trillionnium/crates/trnm-pon-node/src/operator_continuous_recovery.rs",
    "trillionnium/crates/trnm-pon-node/src/operator_continuous_lease.rs",
    "trillionnium/crates/trnm-pon-node/src/operator_continuous_controller.rs",
    "trillionnium/crates/trnm-pon-node/src/store/operator_continuous_owner.rs",
    "trillionnium/crates/trnm-pon-node/src/store/funding/payment.rs",
    "trillionnium/crates/trnm-pon-node/src/store/authenticated_pending_activation.rs",
    "trillionnium/crates/trnm-pon-node/src/store.rs",
    "trillionnium/crates/trnm-pon-node/src/store/pq_network.rs",
    "trillionnium/crates/trnm-pon-node/src/native_authenticated_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/account_archive_execution/state_witness.rs",
    "trillionnium/crates/trnm-pon-node/src/store/native_authenticated/arithmetic_cache.rs",
    "trillionnium/crates/trnm-pon-node/src/store/native_authenticated/arithmetic_cache/root_arithmetic.rs",
    "trillionnium/crates/trnm-pon-node/src/store/native_authenticated/arithmetic_cache/root_arithmetic/tests.rs",
    "trillionnium/crates/trnm-pon-node/src/store/native_authenticated/arithmetic_cache/large_input_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/main.rs",
    "trillionnium/crates/trnm-pon-node/tests/cli_secret_canary.rs",
    "trillionnium/crates/trnm-crypto-primitives/src/pq_auth.rs",
    "trillionnium/crates/trnm-crypto-primitives/src/lib.rs",
    "trillionnium/crates/trnm-crypto-primitives/Cargo.toml",
    "trillionnium/crates/trnm-crypto-primitives/src/pq_auth/tests.rs",
    "trillionnium/crates/trnm-crypto-primitives/examples/pq_message_oracle.rs",
    "trillionnium/crates/trnm-crypto-primitives/tests/independent_backend/differential.py",
    "trillionnium/crates/trnm-crypto-primitives/tests/independent_backend/mldsa_native_differential.py",
    "trillionnium/crates/trnm-crypto-primitives/tests/independent_backend/mldsa_native_oracle.c",
    "trillionnium/crates/trnm-crypto-primitives/tests/independent_backend/test_mldsa_native_source.py",
    "trillionnium/crates/trnm-crypto-primitives/tests/independent_backend/tuf_sdk_differential.py",
    "trillionnium/crates/trnm-crypto-primitives/tests/independent_backend/test_tuf_sdk_source.py",
    "trillionnium/crates/trnm-crypto-primitives/src/pq_auth/tuf.rs",
    "trillionnium/crates/trnm-crypto-primitives/tests/tuf_tap21.rs",
    "trillionnium/crates/trnm-crypto-primitives/tests/tuf_tap21_fixture.py",
    "trillionnium/crates/trnm-crypto-primitives/tests/fixtures/pq/tuf_tap21_mldsa65_v1.json",
    "docs/security/PQ_RELEASE_CURRENT_AUTHORITY_AND_TAP21_V1.md",
    "trillionnium/crates/trnm-crypto-primitives/tests/fixtures/wycheproof/PROVENANCE.md",
    "trillionnium/crates/trnm-crypto-primitives/tests/fixtures/wycheproof/LICENSE",
    "trillionnium/crates/trnm-crypto-primitives/tests/fixtures/wycheproof/mldsa_65_verify_test.json",
    "trillionnium/crates/trnm-crypto-primitives/src/owned_ed25519.rs",
    "trillionnium/crates/trnm-mvcc-fee/Cargo.toml",
    "trillionnium/crates/trnm-mvcc-fee/src/lib.rs",
    "trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs",
    "trillionnium/crates/trnm-mvcc-fee/src/pon_executor/root_arithmetic_tests.rs",
    "trillionnium/crates/trnm-mvcc-fee/src/public_evaluation.rs",
    "trillionnium/crates/trnm-mvcc-fee/src/public_evaluation/quorum_v2.rs",
    "trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts.rs",
    "trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2.rs",
    "trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/application_v6.rs",
    "trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/tasks_v5.rs",
    "trillionnium/crates/trnm-data-availability/Cargo.toml",
    "trillionnium/crates/trnm-data-availability/src/cell.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/pq.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/discovery/pq.rs",
    "trillionnium/crates/trnm-data-availability/src/bin/trnm-cell.rs",
    "trillionnium/crates/trnm-data-availability/src/bin/cell_pq/mod.rs",
    "trillionnium/crates/trnm-data-availability/src/bin/unix/pq.rs",
    "trillionnium/crates/trnm-data-availability/tests/pq_cell_cli.rs",
    "trillionnium/crates/trnm-mvcc-fee/tests/pq_account_owner.rs",
    "trillionnium/crates/trnm-pon-node/tests/pq_account_native.rs",
    "trillionnium/crates/trnm-protocol/src/pq_transaction.rs",
    "trillionnium/crates/trnm-protocol/src/pon_wire.rs",
    "trillionnium/crates/trnm-protocol/src/pon_wire/state_root_arithmetic.rs",
    "trillionnium/crates/trnm-protocol/src/pon_wire/state_root_arithmetic/tests.rs",
    "trillionnium/crates/trnm-protocol/src/pq_native_accounts_v2.rs",
    "trillionnium/crates/trnm-protocol/src/qualified_work_task.rs",
    "trillionnium/crates/trnm-protocol/src/qualified_work_task/pq_lifecycle_v5.rs",
    "trillionnium/Cargo.lock",
    "docs/security/PQ_NATIVE_ACCOUNT_OWNER_V1.md",
))
# These dependencies participate in the same candidate's owner boundaries even
# when their filenames contain no PQ marker. Requiring their actual bytes does
# not make TCD content addressing, M12 readback or a migration rehearsal a PQ
# authorization scheme. They retain their original independently selected owners.
CONVERGENCE_REQUIRED_PATHS = frozenset((
    # The existing History readback owner is now part of this candidate too.
    # Its SQLite observer and exact dependency graph are security-relevant even
    # though neither is a PQ signature implementation or a release approval.
    "config/portability-inventory-v1.json",
    "trillionnium/Cargo.toml",
    "tests/fuzz/Cargo.toml",
    "tests/fuzz/Cargo.lock",
    "trillionnium/crates/trnm-sqlite-io-boundary/Cargo.toml",
    "trillionnium/crates/trnm-sqlite-io-boundary/build.rs",
    "trillionnium/crates/trnm-sqlite-io-boundary/build_loader_paths.rs",
    "trillionnium/crates/trnm-sqlite-io-boundary/unix_layout_witness.c",
    "trillionnium/crates/trnm-sqlite-io-boundary/src/lib.rs",
    "trillionnium/crates/trnm-sqlite-io-boundary/src/ledger.rs",
    "trillionnium/crates/trnm-sqlite-io-boundary/src/owner.rs",
    "trillionnium/crates/trnm-sqlite-io-boundary/src/sql.rs",
    "trillionnium/crates/trnm-sqlite-io-boundary/src/transaction_scope.rs",
    "trillionnium/crates/trnm-sqlite-io-boundary/src/unix_abi.rs",
    "trillionnium/crates/trnm-sqlite-io-boundary/src/unsupported.rs",
    "trillionnium/crates/trnm-sqlite-io-boundary/src/vfs.rs",
    "trillionnium/crates/trnm-pon-node/src/store/native_authenticated.rs",
    "trillionnium/crates/trnm-pon-node/src/store/native_authenticated/post_write_readback.rs",
    "trillionnium/crates/trnm-pon-node/src/store/native_authenticated/post_write_readback/tests.rs",
    "trillionnium/crates/trnm-pon-node/src/store/append_readback_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/store/reorg_cancellation.rs",
    "config/systemd/trnmponpublic.slice",
    "trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/public_v3/request_observation.rs",
    ".github/workflows/trnm-required-baseline.yml",
    ".github/workflows/pon-recent-batch-acceptance.yml",
    ".github/workflows/pon-branch-encoding-acceptance.yml",
    "scripts/ci/check_public_readiness_evidence.py",
    "scripts/ci/test_public_readiness_evidence.py",
    "docs/development/specs/pon/W1_ACTUAL_REUSE_OBSERVATION_V3.md",
    "scripts/ci/run_w1_reused_cost_v3.py",
    "scripts/ci/test_run_w1_reused_cost_v3.py",
    "scripts/ci/test_pon_w1_reused_cost_reader_v3.py",
    "scripts/pon_w1_cost_matrix_reader.py",
    "scripts/pon_w1_reused_cost_reader_v3.py",
    "trillionnium/crates/trnm-pon-node/examples/pon_w1_cost_matrix_v2.rs",
    "trillionnium/crates/trnm-pon-node/examples/pon_w1_reused_cost_v3.rs",
    "trillionnium/crates/trnm-pon-node/examples/support/w1_cost_producers.rs",
    "docs/development/specs/pon/CELL_ORDINARY_HOST_HANDOFF_V2.md",
    "scripts/ci/ci_job.sh",
    "scripts/ci/check_ci_contract.py",
    "scripts/ci/test_ci_contract.py",
    "scripts/ci/test_llm_cell_host_handoff.py",
    "scripts/ci/test_llm_cell_installed_host.py",
    "scripts/ci/run_llm_cell_installed_host_controls.sh",
    "scripts/llm_cell_host_handoff.py",
    "scripts/llm_cell_installed_executable.py",
    "scripts/run_llm_cell_native_handoff.py",
    "docs/development/specs/pon/CELL_DEPENDENCY_CLOSURE_V1.md",
    "docs/security/HEPTA_PQ_HANDOFF_V2_20261031.md",
    "docs/security/PQ_AUTHORITY_SURFACE_AUDIT_20261031.md",
    "docs/security/WHOLE_CHAIN_PQ_CLAIM_GUARD_20261031.md",
    "scripts/ci/pq_authority_surface_scan.py",
    "scripts/ci/test_pq_authority_surface_scan.py",
    "scripts/ci/pq_chain_claim_guard.py",
    "scripts/ci/test_pq_chain_claim_guard.py",
    "formal/pon-nakamoto-v1/cell_dependency_closure.py",
    "formal/pon-nakamoto-v1/test_cell_dependency_closure.py",
    "formal/pon-nakamoto-v1/vectors/cell-dependency-closure-v1.json",
    "trillionnium/crates/trnm-research-protocol/Cargo.toml",
    "trillionnium/crates/trnm-research-protocol/src/lib.rs",
    "trillionnium/crates/trnm-research-protocol/src/hepta_handoff.rs",
    "trillionnium/crates/trnm-research-protocol/src/hepta_handoff/pq.rs",
    "trillionnium/crates/trnm-research-protocol/tests/hepta_handoff_pq.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/closure.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/closure_tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/discovery/sequence_tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/manifest.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/network.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/release.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/release_tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/retention.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/retention/tests.rs",
    "trillionnium/crates/trnm-data-availability/src/bin/cell_closure/mod.rs",
    "trillionnium/crates/trnm-data-availability/tests/cell_closure_cli.rs",
    "trillionnium/crates/trnm-service-settlement/Cargo.toml",
    "trillionnium/crates/trnm-service-settlement/src/lib.rs",
    "trillionnium/crates/trnm-service-settlement/src/native_budget.rs",
    "trillionnium/crates/trnm-service-settlement/src/native_budget/tests.rs",
    "trillionnium/crates/trnm-pon-node/src/store/funding.rs",
    "trillionnium/crates/trnm-pon-node/src/store/funding/tests.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service/tests.rs",
    "trillionnium/crates/trnm-pon-node/src/store/authenticated_migration/growth_rehearsal.rs",
))
# Reused model research and SQLite controls keep their own qualification
# boundaries; source coverage never turns their observations into acceptance.
CONVERGENCE_REQUIRED_PATHS |= frozenset((
    "config/pon/binary-diverse60-training-v3.json",
    "docs/protocol/pon-nakamoto-v1/details/CELL_P2P_V1.md",
    "scripts/ci/model-runtime-cpu-requirements.txt",
    "scripts/ci/runtime-release-requirements.txt",
    "scripts/ci/run_cross_arch_cost.py",
    "scripts/llm_answer_eos_research_v3.py",
    "scripts/llm_answer_eos_task_research_v4.py",
    "scripts/llm_binary_answer_observed_v2.py",
    "scripts/llm_binary_diverse60_observed_v3.py",
    "scripts/llm_cell_release.py",
    "scripts/llm_base_material.py",
    "scripts/test_llm_base_material.py",
    "scripts/test_llm_base_material_torch.py",
    "scripts/test_llm_base_source_closure.py",
    "scripts/llm_initial_trainable_setup_v2.py",
    "scripts/llm_runtime_candidate_observation_v1.py",
    "scripts/llm_runtime_exit_worker_observation.py",
    "scripts/llm_runtime_observed_execution_v1.py",
    "scripts/llm_runtime_parent_step.py",
    "scripts/llm_runtime_parent_step_task_v2.py",
    "scripts/llm_runtime_parent_step_v2.py",
    "scripts/llm_runtime_release.py",
    "scripts/test_llm_answer_eos_loss_v3.py",
    "scripts/test_llm_answer_eos_research_v3.py",
    "scripts/test_llm_answer_eos_task_research_v4.py",
    "scripts/test_llm_binary_answer_observed_v2.py",
    "scripts/test_llm_binary_diverse60_observed_v3.py",
    "scripts/test_llm_cell_release.py",
    "scripts/test_llm_initial_trainable_setup_v2.py",
    "scripts/test_llm_runtime_candidate_observation_v1.py",
    "scripts/test_llm_runtime_exit_worker_observation.py",
    "scripts/test_llm_runtime_observed_execution_v1.py",
    "scripts/test_llm_runtime_parent_step_task_v2.py",
    "scripts/test_llm_runtime_parent_step_v2.py",
    "scripts/test_llm_runtime_release.py",
    "trillionnium/crates/trnm-data-availability/src/cell/cache_budget.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/cache_wal.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/cache_wal_tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/store.rs",
    "trillionnium/crates/trnm-sqlite-io-boundary/build_loader_paths_tests.rs",
    "trillionnium/crates/trnm-sqlite-io-boundary/src/transaction_scope_tests.rs",
    "trillionnium/crates/trnm-sqlite-io-boundary/tests/native_held_directory_v1.rs",
    "trillionnium/crates/trnm-sqlite-io-boundary/tests/native_public_api_v2.rs",
))
# The complete Cell model-storage composition is part of this candidate even
# when no path contains a PQ marker. Pins cover the actual codecs, payload
# readers, protocol versions and negative controls. This adds no publisher,
# CURRENT/FinalUse, independent-retention or production qualification claim.
CONVERGENCE_REQUIRED_PATHS |= frozenset((
    "docs/development/specs/pon/CELL_MODEL_STORAGE_V1.md",
    "docs/development/specs/pon/CELL_RETENTION_V1.md",
    "formal/pon-nakamoto-v1/model_release_root.py",
    "formal/pon-nakamoto-v1/test_model_release_root.py",
    "formal/pon-nakamoto-v1/vectors/cell-model-root-v1.json",
    "trillionnium/crates/trnm-data-availability/src/lib.rs",
    "trillionnium/crates/trnm-data-availability/examples/cell_residency_observer.rs",
    "trillionnium/crates/trnm-data-availability/src/bin/cell_model/mod.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/archive.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/archive_tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/delta.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/delta_tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/delta_network_tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/discovery.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/discovery/diversity_tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/discovery/selection.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/discovery/transport.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/discovery/pq/tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/discovery/pq/transport.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/model_root.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/model_root_tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/network/availability.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/network/availability/tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/network/dedup_tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/network/persistent.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/network/persistent/tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/network/serving.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/network/serving/tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/release/transport_tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/residency.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/residency_tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/tensor.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/tensor_reader.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/tensor_tests.rs",
    "trillionnium/crates/trnm-data-availability/tests/cell_persistent_cli.rs",
    "trillionnium/crates/trnm-data-availability/tests/cell_tensor_cli.rs",
))
# Explicit inventory-over-persistent composition and single-object height-window
# admission keep their real refusal/recovery controls in the same source set.
CONVERGENCE_REQUIRED_PATHS |= frozenset((
    "trillionnium/crates/trnm-data-availability/src/cell/network/persistent/rarest_tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/release/transport_tests/rarest.rs",
    "trillionnium/crates/trnm-data-availability/tests/cell_persistent_cli/rarest.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service/height_window_tests.rs",
))
# Exact consumer and business-path bytes for the request/working-state/data
# continuation. Observation output is never execution authority, and these
# finite resource checks do not establish host isolation or public acceptance.
# Same-operation checked multiproofs and the post-snapshot epoch owner are
# required dependencies even though their filenames do not identify PQ code.
CONVERGENCE_REQUIRED_PATHS |= frozenset((
    "scripts/pon_public_v3_phase_read.py",
    "scripts/ci/test_pon_public_v3_phase_read.py",
    "trillionnium/crates/trnm-pon-node/src/account_archive_prototype/multiproof.rs",
    "trillionnium/crates/trnm-pon-node/src/account_archive_prototype/multiproof_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/store/evaluation_observation.rs",
    "trillionnium/crates/trnm-pon-node/src/store/evaluation_round_observation.rs",
    "trillionnium/crates/trnm-pon-node/src/store/growth.rs",
    "trillionnium/crates/trnm-pon-node/src/store/growth/observation.rs",
    "trillionnium/crates/trnm-pon-node/src/growth_cli.rs",
    "trillionnium/crates/trnm-pon-node/tests/native_growth_cli.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/network/serving.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/network/serving/tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/tests.rs",
))
# The ordinary Cell loader now consumes a separately pinned installed Python
# runtime. Cover its real bootstrap/import dependencies and both discovery
# deadline owners; these pins neither execute the model nor certify a DHT.
CONVERGENCE_REQUIRED_PATHS |= frozenset((
    "scripts/llm_neural_read_worker.py",
    "scripts/llm_python_runtime_contract.py",
    "scripts/test_llm_neural_read_worker.py",
    "scripts/test_llm_material_runtime_bridge.py",
    "scripts/test_llm_material_runtime_entry.py",
    "tests/fixtures/llm_material_runtime_bridge_v1/historical_plan.json",
    "tests/fixtures/llm_material_runtime_bridge_v1/historical_target.json",
    "scripts/test_llm_python_runtime_contract.py",
    "formal/pon-nakamoto-v1/llm_adapter_contract.py",
    "scripts/llm_parent_material.py",
    "scripts/llm_inherited_runtime.py",
    "scripts/llm_runtime_pilot.py",
    "formal/pon-nakamoto-v1/contract_wire.py",
    "config/pon/ledger-v1.json",
    "config/pon/model-family-v1.json",
    "config/pon/model-family-smollm2-135m-v1.json",
    "config/pon/work-profile-v1.json",
    "scripts/run_smollm_cell_replica_research.py",
    "scripts/ci/test_llm_cell_handoff_deadline.py",
    "trillionnium/crates/trnm-data-availability/src/cell/discovery/directory.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/discovery/pq/directory.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/discovery/directory_wait.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/discovery/directory_deadline_tests.rs",
))
# Six-workpackage observations retain their exact reader, sampler and recovery
# owner bytes. Their inclusion does not promote a local measurement or an old
# receipt to whole-Cell, independent-operation or production acceptance.
CONVERGENCE_REQUIRED_PATHS |= frozenset((
    "config/pon/w1-retained-disposition-v1.json",
    "scripts/read_w1_full_v2_disposition.py",
    "scripts/pon_w1_preparation_strategy_reader_v4.py",
    "scripts/ci/test_six_workpackage_native_rosters.py",
    "scripts/ci/test_authenticated_suite_count.py",
    "scripts/ci/test_w1_full_v2_disposition.py",
    "scripts/ci/test_pon_w1_preparation_strategy_reader_v4.py",
    "trillionnium/crates/trnm-pon-node/examples/pon_w1_preparation_strategy_v4.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service/replay_owner_tests.rs",
    "evidence/pon-six-workpackages-20261106/strategy/run_campaign.py",
    "evidence/pon-six-workpackages-20261106/strategy/summarize_costs.py",
    "evidence/pon-six-workpackages-20261106/strategy/package_raw.py",
))
# Shared-domain scheduling, bounded live counter reads and adjacent ancestry
# material reuse keep their owners and adversarial controls in this same source
# contract. Cost readback is observational and never grants current authority.
CONVERGENCE_REQUIRED_PATHS |= frozenset((
    "docs/protocol/pon-nakamoto-v1/details/PUBLIC_POOL_INTAKE_V3.md",
    "scripts/ci/throughput_cost_coverage.py",
    "scripts/ci/test_throughput_cost_coverage.py",
    "trillionnium/crates/trnm-pon-node/src/host_kernel_parent_resource_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/public_v3/intake.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/public_v3/intake/shared_readiness_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/public_v3/intake_domain_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/store/observed_history.rs",
    "trillionnium/crates/trnm-pon-node/src/store/observed_history/tests.rs",
    "trillionnium/crates/trnm-pon-node/src/store/native_authenticated/post_write_readback/history_record_tests.rs",
    "trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/parallel_preparation_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/pq_network/parallel_execution_tests.rs",
))
NATIVE_REQUIRED_PATHS |= CONVERGENCE_REQUIRED_PATHS
RECOVERY_RELEASE_REQUIRED_PATHS = frozenset((
    "trillionnium/crates/trnm-checkpoint-store/Cargo.toml",
    "trillionnium/crates/trnm-checkpoint-store/src/lib.rs",
    "trillionnium/crates/trnm-checkpoint-store/src/main.rs",
    "trillionnium/crates/trnm-checkpoint-store/src/journal_checkpoint_v1.rs",
    "trillionnium/crates/trnm-checkpoint-store/src/live_journal_v2.rs",
    "trillionnium/crates/trnm-checkpoint-store/src/node_commit_ledger_v1.rs",
    "trillionnium/crates/trnm-checkpoint-store/tests/cross_process.rs",
    "trillionnium/crates/trnm-checkpoint-store/tests/cold_recovery.rs",
    "trillionnium/crates/trnm-release-bundle/Cargo.toml",
    "trillionnium/crates/trnm-release-bundle/src/lib.rs",
    "trillionnium/crates/trnm-release-bundle/src/pq_release.rs",
    "trillionnium/crates/trnm-release-bundle/src/pq_release/current_tests.rs",
    "trillionnium/crates/trnm-release-bundle/src/pq_release/initial_root_material.rs",
    "trillionnium/crates/trnm-release-bundle/src/pq_release/initial_root_material_tests.rs",
    "config/pon/pq-initial-root-material-required-tests-v1.json",
    "trillionnium/crates/trnm-release-bundle/src/pq_release/bundle_quorum.rs",
    "trillionnium/crates/trnm-release-bundle/src/pq_release/bundle_quorum_tests.rs",
    "trillionnium/crates/trnm-release-bundle/src/pq_release/validated_root_tests.rs",
    "trillionnium/crates/trnm-release-bundle/src/pq_release/retained_verifier_tests.rs",
    "trillionnium/crates/trnm-release-bundle/src/pq_release/tests.rs",
    "formal/pon-nakamoto-v1/pq_mtls_probe.c",
    "formal/pon-nakamoto-v1/test_pq_mtls_probe.py",
    "formal/pon-nakamoto-v1/test_pq_tls.py",
    "formal/pon-nakamoto-v1/pq_openssl_backend.py",
    "docs/security/PQ_RECOVERY_RELEASE_TRANSPORT_BOUNDARIES_V1.md",
))
NATIVE_REQUIRED_PATHS |= RECOVERY_RELEASE_REQUIRED_PATHS
NATIVE_FALSE = frozenset((
    "whole_native_authorization_migrated", "default_profile_migrated",
    "allow_legacy_fallback", "production_activation", "public_wan_accepted",
    "physical_rollback_resistant",
))

# These are bounded source contracts, not results of a cryptographic audit.
# In particular, an always-compiled provider is not default chain activation.
NATIVE_V2_EXPECTED = {
    "profile": "native-pq-network-owner-v2",
    "feature": "canonical-default-no-feature-required",
    "canonical_provider": "RustCrypto/ml-dsa-0.1.1",
    "independent_provider": "pq-native-openssl-differential-only-no-fallback",
    "scope": "fresh explicitly selected PNQ2 transport owner; account/task authorization remains the original separately selected M06 owner",
    "contract": "docs/security/PQ_NATIVE_NETWORK_OWNER_V2.md",
    "request_wire": "PNQ2/v2",
    "response_wire": "PNP2/v2",
    "activation_rule": "protected-settings-fresh-namespace-no-input-negotiation",
    "transport_confidentiality": "loopback-signed-plaintext-dev-only",
    "canonical_crypto_available_by_default": True,
    "tpq1_peer_purpose": 6,
    "signed_frame_bytes": 3487,
    "signature_bytes": 3309,
    "spki_bytes": 1974,
    "maximum_wire_bytes": 2097152,
    "ledger_byte_limit": 16777216,
    "ledger_record_limit": 4096,
    "ingress_connection_limit": 64,
    "ingress_byte_limit": 33554432,
    "inbound_verification_limit": 64,
    "signature_independent_operation_identity": True,
    "reorg_independent_local_revocation": True,
    "durable_ingress_budget": True,
    "failed_verifications_refunded": False,
    "default_chain_activation": False,
    "continuous_npq6_fresh_namespace_implemented": True,
    "continuous_npq6_contract": "docs/security/PQ_CONTINUOUS_STARTUP_V3.md",
    "continuous_npq6_combination_accepted": False,
    "research_archive_pq_accepted": False,
    "cli_automatic_parent_recovery_pq_accepted": False,
    **{flag: False for flag in NATIVE_FALSE},
}


def is_pq_source(parts: tuple[str, ...]) -> bool:
    """Recognize pq.rs, cell_pq and operator_pq_auth as well as older prefixes."""
    return any(
        part.startswith(("pq_", "pqg_", "pql"))
        or re.search(r"(?:^|_)pq(?:_|$)", Path(part).stem)
        for part in parts
    )

class IntegrityError(ValueError):
    pass


def _safe_regular(root: Path, relative: str, ceiling: int = 4 * 1024 * 1024) -> bytes:
    if (type(relative) is not str or not relative or "\\" in relative
            or relative.startswith("/") or relative.split("/") != list(Path(relative).parts)
            or any(p in ("", ".", "..") for p in relative.split("/"))):
        raise IntegrityError("unsafe path")
    path = root
    for part in relative.split("/"):
        path = path / part
        if path.is_symlink():
            raise IntegrityError("symlink source refused: " + relative)
    try:
        st = path.stat()
    except OSError as exc:
        raise IntegrityError("missing source: " + relative) from exc
    if not stat.S_ISREG(st.st_mode) or st.st_size > ceiling:
        raise IntegrityError("nonregular/oversize source: " + relative)
    data = path.read_bytes()
    if len(data) != st.st_size:
        raise IntegrityError("changing source: " + relative)
    return data


def _json(root: Path, relative: str) -> dict:
    def unique_pairs(pairs):
        result = {}
        for key, val in pairs:
            if key in result:
                raise IntegrityError("duplicate JSON key")
            result[key] = val
        return result
    try:
        value = json.loads(_safe_regular(root, relative), object_pairs_hook=unique_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrityError("noncanonical JSON document: " + relative) from exc
    if not isinstance(value, dict):
        raise IntegrityError("expected JSON object: " + relative)
    return value


def _git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def _check_canonical_provider_contract(root: Path) -> None:
    """Check real Cargo declarations in addition to their reviewed source pins."""
    manifests = {}
    for name in ("trnm-crypto-primitives", "trnm-mvcc-fee", "trnm-pon-node"):
        relative = f"trillionnium/crates/{name}/Cargo.toml"
        try:
            value = tomllib.loads(_safe_regular(root, relative).decode("utf-8"))
        except (UnicodeError, tomllib.TOMLDecodeError) as exc:
            raise IntegrityError("canonical provider manifest invalid") from exc
        package = value.get("package", {})
        features = value.get("features", {})
        dependencies = value.get("dependencies", {})
        if any(not isinstance(table, dict) for table in (package, features, dependencies)):
            raise IntegrityError("canonical provider manifest table invalid")
        package_metadata = package.get("metadata", {})
        if not isinstance(package_metadata, dict):
            raise IntegrityError("canonical provider manifest table invalid")
        metadata = package_metadata.get("trnm", {})
        if not isinstance(metadata, dict):
            raise IntegrityError("canonical provider manifest table invalid")
        openssl = dependencies.get("openssl", {})
        if (features.get("default") != []
                or "pq-native-openssl" not in features
                or not isinstance(openssl, dict)
                or openssl.get("optional") is not True
                or metadata.get("production_activation") is not False
                or metadata.get("consensus_authority") is not False):
            raise IntegrityError("canonical provider/default activation contract changed")
        manifests[name] = value
    provider = manifests["trnm-crypto-primitives"].get("dependencies", {}).get("ml-dsa")
    if (not isinstance(provider, dict) or provider.get("version") != "=0.1.1"
            or provider.get("optional", False) is not False
            or provider.get("default-features") is not False
            or not isinstance(provider.get("features"), list)
            or any(type(feature) is not str for feature in provider["features"])
            or sorted(provider.get("features", [])) != ["alloc", "zeroize"]):
        raise IntegrityError("canonical ML-DSA provider contract changed")


def _check_pq_source_coverage(root: Path, pins: dict[str, str]) -> None:
    """Fail closed when a newly added PQ implementation evades the blob manifest."""
    for directory in PQ_SOURCE_DIRS:
        parent = root / directory
        if parent.is_symlink() or not parent.is_dir():
            raise IntegrityError("missing or symlink PQ source directory: " + directory)
        # Every descendant matters: a future verifier in experiments/ or an
        # owner submodule must not evade the fixed-source manifest.
        pending = [parent]
        visited = 0
        while pending:
            current = pending.pop()
            for source in current.iterdir():
                visited += 1
                if visited > 10000:
                    raise IntegrityError("PQ source traversal budget exhausted")
                relative = source.relative_to(root).as_posix()
                if source.is_symlink():
                    raise IntegrityError("symlink PQ source entry refused: " + relative)
                if source.is_dir():
                    pending.append(source)
                    continue
                # Nested Rust/C/Python files inside a PQ-named module are
                # implementations too, even when called native.rs or mod.rs.
                parts = source.relative_to(parent).parts
                if source.suffix not in (".py", ".c", ".rs") or (
                    directory not in COMPLETE_OWNER_SOURCE_DIRS and not is_pq_source(parts)
                ):
                    continue
                if relative not in pins:
                    raise IntegrityError("unpinned PQ source: " + relative)
                # A pinned path is already byte-checked by check(); never
                # treat source enumeration as cryptographic authority.

def check(root: Path) -> dict:
    root = Path(root).resolve(strict=True)
    m = _json(root, REL_MANIFEST)
    if m.get("schema") != "trnm-pq-cross-branch-corpus-v1" or m.get("status") != "research-only-hold-no-go":
        raise IntegrityError("corpus must remain research/HOLD")
    if m.get("parent_profile") != "pon-nakamoto-v1":
        raise IntegrityError("wrong profile")
    heads = m.get("upstream_heads")
    if not isinstance(heads, dict) or set(heads) != REQUIRED_UPSTREAM:
        raise IntegrityError("missing provenance parent")
    if not all(type(v) is str and re.fullmatch("[0-9a-f]{40}", v) for v in heads.values()):
        raise IntegrityError("malformed provenance commit")
    assertions = m.get("assertions")
    if not isinstance(assertions, dict) or set(assertions) != REQUIRED_FALSE:
        raise IntegrityError("missing acceptance gate")
    if any(value is not False for value in assertions.values()):
        raise IntegrityError("unaccepted capability claimed true")
    pins = m.get("pinned_blobs")
    required = m.get("required_paths")
    if (not isinstance(pins, dict) or not isinstance(required, list)
            or not required or len(required) != len(set(required))
            or any(type(p) is not str or p not in pins for p in required)):
        raise IntegrityError("incomplete source pins")
    for relative, sha in pins.items():
        if type(sha) is not str or not re.fullmatch("[0-9a-f]{40}", sha):
            raise IntegrityError("invalid pinned blob")
        if _git_blob(_safe_regular(root, relative)) != sha:
            raise IntegrityError("changed source: " + relative)
    _check_pq_source_coverage(root, pins)
    # PNQ1/OpenSSL-only records remain historical evidence, not the active
    # source contract for this canonical-provider PNQ2 candidate.
    if "native_network_owner_slice_v1" in m:
        raise IntegrityError("superseded PNQ1 native slice cannot select this candidate")
    native = m.get("native_network_owner_slice_v2")
    if (not isinstance(native, dict)
            or set(native) != set(NATIVE_V2_EXPECTED) | {"evidence"}
            or any(type(native.get(key)) is not type(value) or native.get(key) != value
                   for key, value in NATIVE_V2_EXPECTED.items())
            or not NATIVE_REQUIRED_PATHS.issubset(required)):
        raise IntegrityError("canonical PNQ2 bounded-profile contract changed")
    _check_canonical_provider_contract(root)
    evidence = native.get("evidence")
    if (type(evidence) is not str
            or not evidence.startswith(("evidence/", "qualification/"))
            or not evidence.endswith("/README.md")):
        raise IntegrityError("native PQ evidence locator")
    # Presence/readability is not test acceptance. The report must distinguish
    # recovered executable measurements from newly compiled exact-source runs.
    _safe_regular(root, evidence)
    account = m.get("native_account_owner_slice_v1")
    if (not isinstance(account, dict)
            or account.get("profile") != "native-pq-qtx1-account-v1"
            or account.get("feature") != "pq-native-openssl"
            or account.get("contract") != "docs/security/PQ_NATIVE_ACCOUNT_OWNER_V1.md"
            or account.get("evidence") != "evidence/pon-pq-account-native-20261028/README.md"
            or account.get("migration_wire") != "PQG1/v1"
            or account.get("transaction_wire") != "QTX1/v1"
            or type(account.get("transaction_byte_limit")) is not int
            or account["transaction_byte_limit"] != 8192
            or type(account.get("transaction_count_limit")) is not int
            or account["transaction_count_limit"] != 16
            or account.get("liability_mode") != "all-source-records-locked"
            or account.get("transfer_only") is not True
            or account.get("original_m06_nonce_fee_owner") is not True
            or account.get("dual_possession_signatures_required") is not True
            or account.get("miner_roster_permission_required") is not False
            or account.get("independent_source_history_authenticated") is not False
            or any(account.get(flag) is not False for flag in NATIVE_FALSE)):
        raise IntegrityError("native PQ account bounded-profile contract changed")
    _safe_regular(root, account["evidence"])
    overwrites = m.get("overwrites")
    expected_overwrites = {
        "formal/pon-nakamoto-v1/pq_cell_custody.py": "cell",
        "formal/pon-nakamoto-v1/pq_account_migration.py": "migration",
        "formal/pon-nakamoto-v1/pq_pql5_quorum.py": "witness",
        "formal/pon-nakamoto-v1/test_pq_pql5_quorum.py": "witness",
    }
    if overwrites != expected_overwrites:
        raise IntegrityError("unreviewed source substitution")
    actual_consensus = _json(root, "config/consensus-mainline.json")
    actual_devnet = _json(root, "config/pon/devnet-v1.json")
    pq = _json(root, "config/pon/post-quantum-transition-v1.json")
    if (actual_consensus.get("production_consensus_activation") is not False
            or actual_consensus.get("runtime_implemented") is not False
            or actual_consensus.get("active_consensus_implementation") is not None
            or actual_devnet.get("production_activation") is not False
            or actual_devnet.get("max_transaction_bytes") != 2048
            or pq.get("production_activation") is not False
            or pq.get("allow_classical_fallback") is not False
            or pq.get("reference_signature", {}).get("signature_bytes") != 3309
            or pq.get("existing_devnet_limits", {}).get("post_quantum_transaction_wire_compatible") is not False):
        raise IntegrityError("installed consensus or PQ gate changed")
    return {
        "schema": "trnm-pq-cross-branch-check-v1", "status": "HOLD_NO_GO",
        "exact_source_blobs": len(pins), "upstream_heads": len(heads),
        "cryptographic_acceptance": False, "node_activated": False,
        "whole_native_authorization_migrated": False,
        "native_transport_contract_checked": True,
        "native_transfer_account_contract_checked": True,
        "canonical_pnq2_contract_checked": True,
        "canonical_default_provider_contract_checked": True,
        "legacy_qtx1_optional_adapter_contract_checked": True,
        "continuous_npq6_combination_accepted": False,
        "production_confidentiality_accepted": False,
    }


if __name__ == "__main__":
    try:
        print(json.dumps(check(Path(__file__).resolve().parents[2]), sort_keys=True))
    except (IntegrityError, OSError, ValueError) as exc:
        print("HOLD_NO_GO: " + str(exc), file=sys.stderr)
        sys.exit(1)
