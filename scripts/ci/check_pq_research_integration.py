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
import sys
import tomllib

from pq_source_reader import SourceReadError, read_regular

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
    "trillionnium/crates/trnm-data-availability/examples",
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
    "trillionnium/crates/trnm-pon-node/src/root_recovery_v3",
)

# Every implementation file in these dedicated security owners participates in
# the boundary, including recovery helpers without a PQ-prefixed filename.
COMPLETE_OWNER_SOURCE_DIRS = frozenset((
    "trillionnium/crates/trnm-release-bundle",
    "trillionnium/crates/trnm-checkpoint-store",
    "trillionnium/crates/trnm-pon-node/src/root_recovery_v3",
))

# This is a newly reconstructed source contract. The old, lost checker bytes
# are not recreated by claiming their historical Git object identity. The
# transport slice remains mandatory and separately bounded from whole-chain PQ.
NATIVE_REQUIRED_PATHS = frozenset((
    "config/pon/w1-lifetime-current-source-v2.json",
    "config/pon/w1-qrom-closure-current-required-tests-v2.json",
    "scripts/w1_lifetime_current_observation.py",
    "scripts/ci/test_w1_lifetime_current_observation.py",
    "scripts/ci/w1_qrom_closure_current_controls.py",
    "scripts/ci/test_w1_qrom_closure_current_controls.py",
    "docs/security/W1_LIFETIME_CURRENT_SOURCE_OBSERVATION_V2.md",
    "scripts/ci/pq_source_reader.py",
    "config/pon/w1-stark-route-registry-v1.json",
    "config/pon/w1-stark-literature-evidence-v1.json",
    "scripts/w1_stark_field_certificates.py",
    "scripts/w1_stark_route_audit.py",
    "scripts/ci/test_w1_stark_field_certificates.py",
    "scripts/ci/test_w1_stark_route_audit.py",
    "scripts/w1_fri_query_replay.py",
    "scripts/ci/test_w1_fri_ideal_sampler.py",
    "docs/security/W1_STARK_ROUTE_INSTANCE_AUDIT_V1.md",
    "docs/protocol/pon-nakamoto-v1/details/STARK_THREE_ROUTE_LITERATURE_20261109.md",
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
    "scripts/ci/pinned_native_process.py",
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
    "config/pon/local-resource-owner-v1.json",
    "trillionnium/crates/trnm-pon-node/src/store/packet_observation.rs",
    "trillionnium/crates/trnm-pon-node/src/packet_observer_cli.rs",
    "trillionnium/crates/trnm-pon-node/src/store/growth/observer.rs",
    "trillionnium/crates/trnm-pon-node/tests/native_packet_observer.rs",
    "trillionnium/crates/trnm-pon-node/src/resource_owner_v1.rs",
    "trillionnium/crates/trnm-pon-node/src/resource_owner_v1_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/packet_observer_cli/owned.rs",
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
    "trillionnium/crates/trnm-mvcc-fee/tests/account_profile_boundary.rs",
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
    "scripts/ci/pq_lifetime_budget.py",
    "scripts/ci/test_pq_lifetime_budget.py",
    "scripts/ci/hash_use_contract.py",
    "scripts/ci/test_hash_use_contract.py",
    "config/pon/hash-use-contract-v1.json",
    "docs/security/HASH_USE_CONTRACT_V1.md",
    "config/pon/pq128-lifetime-budget-v1.json",
    "config/pon/pq128-source-lock-v1.json",
    "config/pon/pq128-lifetime-example-v1.json",
    "formal/pon-nakamoto-v1/pq_root_recovery_policy_v1.py",
    "formal/pon-nakamoto-v1/test_pq_root_recovery_policy_v1.py",
    "docs/security/PQ_ROOT_RECOVERY_POLICY_V1.md",
    "docs/security/PQ_SEVEN_LAYER_REVIEW_20261108.md",
    "scripts/ci/pq_authority_effect_register.py",
    "scripts/ci/test_pq_authority_effect_register.py",
    "config/pon/pq-authority-effects-v1.json",
    "docs/security/PQ_AUTHORITY_EFFECT_REGISTER_V1.md",
    "docs/security/PQ128_LIFETIME_BUDGET_V1.md",
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
    "scripts/pon_proof_latency.py",
    "scripts/read_w1_proof_latency.py",
    "scripts/ci/test_pon_proof_latency.py",
    "scripts/ci/test_w1_proof_latency_readback.py",
    "scripts/pon_w1_preparation_strategy_reader_v4.py",
    "scripts/ci/test_six_workpackage_native_rosters.py",
    "scripts/ci/check_sqlite_build_requalification.py",
    "evidence/pon-six-workpackages-20261106/next/service/run_reorg_abba.py",
    "evidence/pon-six-workpackages-20261106/next/service/test_run_reorg_abba.py",
    "evidence/pon-six-workpackages-20261106/next/service/ABBA_PROTOCOL.md",
    "formal/pon-nakamoto-v1/W1_RANK_BATCH_V5.md",
    "scripts/pon_w1_rank_batch_reader_v5.py",
    "scripts/ci/run_w1_rank_batch_v5.py",
    "scripts/ci/test_pon_w1_rank_batch_reader_v5.py",
    "scripts/ci/test_run_w1_rank_batch_v5.py",
    "scripts/ci/test_w1_factorial_native_gate.py",
    ".github/workflows/pon-w1-work-security.yml",
    "trillionnium/crates/trnm-crypto-primitives/examples/pon_w1_rank_batch_v5.rs",
    "trillionnium/crates/trnm-crypto-primitives/src/pon_work/legal_attempt.rs",
    "trillionnium/crates/trnm-crypto-primitives/src/pon_work/legal_attempt/low_rank.rs",
    "trillionnium/crates/trnm-pon-node/examples/native_reorg_query_cost.rs",
    "trillionnium/crates/trnm-pon-node/src/store/read_query_cache_tests.rs",
    "scripts/ci/test_w1_full_v2_disposition.py",
    "scripts/ci/test_pon_w1_preparation_strategy_reader_v4.py",
    "trillionnium/crates/trnm-pon-node/examples/pon_w1_preparation_strategy_v4.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service/replay_owner_tests.rs",
    "evidence/pon-six-workpackages-20261106/strategy/run_campaign.py",
    "evidence/pon-six-workpackages-20261106/strategy/summarize_costs.py",
    "evidence/pon-six-workpackages-20261106/strategy/package_raw.py",
))
# Post-win runtime, full-v2 retained inputs and asynchronous generation owners
# are source boundaries only. Pins never assert live provider execution, complete
# resource coverage, proof security, Node admission or production activation.
W1_POSTWIN_REQUIRED_PATHS = frozenset((
    ".github/workflows/pon-w1-transparent-profile.yml",
    "scripts/ci/ci_job.sh",
    "scripts/ci/check_ci_contract.py",
    "scripts/ci/test_ci_contract.py",
    "scripts/ci/check_pq_research_integration.py",
    "scripts/ci/test_pq_research_integration.py",
    "formal/pon-nakamoto-v1/experiments/w1_stage_measure.py",
    "formal/pon-nakamoto-v1/experiments/w1_full_staged_run.py",
    "formal/pon-nakamoto-v1/experiments/w1_local_payload.py",
    "scripts/ci/test_w1_cancellation_handoff.py",
    "scripts/ci/test_w1_coordinator_contract.py",
    "scripts/ci/test_w1_postwin_identity.py",
    "scripts/ci/test_w1_kaggle_worker_contract.py",
    "scripts/ci/test_w1_staged_observer.py",
    "formal/pon-nakamoto-v1/w1_v2_verifier/Cargo.toml",
    "formal/pon-nakamoto-v1/w1_v2_verifier/Cargo.lock",
    "formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs",
    "formal/pon-nakamoto-v1/w1_zkvm/host/src/bin/w1-staged-prover.rs",
    "formal/pon-nakamoto-v1/w1_zkvm/host/src/bin/w1_staged_prover/schedule.rs",
    "formal/pon-nakamoto-v1/w1_zkvm/host/src/bin/w1_staged_prover/schedule_tests.rs",
    "formal/pon-nakamoto-v1/w1_zkvm/host/src/bin/w1_staged_prover/recursion_tests.rs",
    "formal/pon-nakamoto-v1/w1_zkvm/host/src/bin/w1_staged_prover/parallel_segments.rs",
    "formal/pon-nakamoto-v1/w1_zkvm/host/src/bin/w1_staged_prover/parallel_segments_tests.rs",
    "formal/pon-nakamoto-v1/w1_zkvm/host/src/bin/w1_staged_prover/guest_identity.rs",
    "formal/pon-nakamoto-v1/w1_zkvm/host-v2/Cargo.toml",
    "formal/pon-nakamoto-v1/w1_zkvm/methods-v2/Cargo.toml",
    "formal/pon-nakamoto-v1/w1_zkvm/methods-v2/build.rs",
    "formal/pon-nakamoto-v1/w1_zkvm/Cargo.lock",
    "formal/pon-nakamoto-v1/w1_zkvm/RETAINED_V2_GUEST.md",
    "evidence/pon-w1-backend-sdk-20261107/fixed-sdk-contract.json",
    "scripts/run_w1_receiver.py",
    "scripts/run_w1_postwin_proof.py",
    "scripts/run_w1_deployment_comparison.py",
    "scripts/audit_w1_deployment_comparison.py",
    "scripts/ci/test_w1_deployment_comparison_audit.py",
    "scripts/ci/test_w1_deployment_evidence_binding.py",
    "scripts/w1_owned_process_collector_v1.py",
    "scripts/test_w1_owned_process_collector_v1.py",
    "scripts/ci/test_w1_receiver_real.py",
    "trillionnium/crates/trnm-crypto-primitives/examples/pon_w1_native_winner_v2.rs",
    "trillionnium/crates/trnm-service-settlement/src/native_generation_budget_v2.rs",
    "trillionnium/crates/trnm-service-settlement/src/native_generation_budget_v2/tests.rs",
    "trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2.rs",
    "trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/task_owner.rs",
    "trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/terminal.rs",
    "trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/tests.rs",
    "trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/tests/terminal.rs",
    "trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/tests/heavy.rs",
    "trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/tests/heavy/cancellation.rs",
    "trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/tests/heavy/cancellation/tests.rs",
    "trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/tests/heavy/cancellation/timeout.rs",
    "trillionnium/crates/trnm-service-settlement/src/lib.rs",
    "trillionnium/crates/trnm-pon-node/src/store.rs",
    "trillionnium/crates/trnm-pon-node/src/lib.rs",
    "scripts/kaggle_generation_contract_v2.py",
    "scripts/test_kaggle_generation_contract_v2.py",
    "scripts/w1_generation_target_v2.py",
    "scripts/test_w1_generation_target_v2.py",
    "scripts/w1_owner_cancellation_v1.py",
    "scripts/test_w1_owner_cancellation_v1.py",
    "scripts/w1_owned_generation_runtime_v2.py",
    "scripts/test_w1_owned_generation_runtime_v2.py",
    "scripts/build_w1_kaggle_source.py",
    "scripts/w1_kaggle_worker_template.py",
    "scripts/ci/test_w1_kaggle_source_builder.py",
    "evidence/pon-w1-full-v2-20261105/succinct.bin",
    "evidence/pon-w1-full-v2-20261105/input.bin",
    "evidence/pon-w1-full-v2-20261105/header.bin",
    "evidence/pon-w1-full-v2-20261105/expected-artifacts.bin",
    "evidence/pon-w1-full-v2-20261105/guest.bin",
    "evidence/pon-w1-full-v2-20261105/asset-sha256.json",
    "evidence/pon-w1-statement-v2-20261105/input-declaration.json",
    "evidence/pon-w1-statement-v2-20261105/expected-artifacts.bin",
))
CONVERGENCE_REQUIRED_PATHS |= W1_POSTWIN_REQUIRED_PATHS
# Funded service admission and durable native operation/evidence owners are
# required source, never independent demand or model-acceptance certificates.
CONVERGENCE_REQUIRED_PATHS |= frozenset((
    'formal/pon-nakamoto-v1/demand_evidence.py',
    'formal/pon-nakamoto-v1/test_demand_evidence.py',
    'formal/pon-nakamoto-v1/upgrade_policy.py',
    'formal/pon-nakamoto-v1/test_upgrade_policy.py',
    'docs/development/specs/pon/DEMAND_EVALUATION_UPGRADE_V1.md',
    'docs/development/specs/pon/FUNDED_SERVICE_TASK_V1.md',
    'docs/development/specs/pon/NATIVE_TASK_EVIDENCE_V1.md',
    'trillionnium/crates/trnm-protocol/src/funded_service_task_v1.rs',
    'trillionnium/crates/trnm-mvcc-fee/src/pon_executor/funded_service_v1.rs',
    'trillionnium/crates/trnm-mvcc-fee/src/pon_executor/funded_service_v1/tests.rs',
    'trillionnium/crates/trnm-pon-node/src/store/demand_evidence.rs',
    'trillionnium/crates/trnm-pon-node/src/store/task_operation_v2.rs',
    'trillionnium/crates/trnm-pon-node/tests/no_gain_fees.rs',
    'trillionnium/crates/trnm-pon-node/tests/funded_service_contract.rs',
    'trillionnium/crates/trnm-pon-node/tests/native_demand_evidence.rs',
    'trillionnium/crates/trnm-service-settlement/src/native_budget/evidence.rs',
    'trillionnium/crates/trnm-service-settlement/src/native_budget/task_operation_v2.rs',
))
CONVERGENCE_REQUIRED_PATHS |= frozenset((
    'docs/development/specs/pon/NATIVE_TASK_OPERATION_V2.md',
    'trillionnium/crates/trnm-pon-node/tests/native_task_operation_v2.rs',
    'trillionnium/crates/trnm-service-settlement/src/native_budget/task_operation_v2/tests.rs',
))
CONVERGENCE_REQUIRED_PATHS |= frozenset((
    'trillionnium/crates/trnm-pon-node/tests/native_active_anchor.rs',
    'trillionnium/crates/trnm-pon-node/src/store/task_operation_v2/reconciliation.rs',
))
# Explicit current report observers retain their exact sources and tests.
# This coverage does not promote selected-byte observations or retained controls
# to cryptographic, independent Host, or complete lifetime qualification.
CONVERGENCE_REQUIRED_PATHS |= frozenset((
    "scripts/ci/w1_v2_controls_gate.py",
    "scripts/ci/test_w1_v2_current_stage_gate.py",
    "scripts/w1_current_source_observation.py",
    "scripts/ci/test_w1_current_source_observation.py",
    "config/pon/w1-qrom-current-source-observation-v1.json",
    "docs/security/W1_QROM_CURRENT_SOURCE_OBSERVATION_DESIGN_20261108.md",
    "scripts/w1_qrom_current_implementation_audit.py",
    "scripts/ci/test_w1_qrom_current_implementation_audit.py",
    "config/pon/w1-qrom-implementation-current-v2.json",
    "docs/security/W1_QROM_CURRENT_SOURCE_MAPPING_V2.md",
))
# The business observer is source-bound independently of historical campaign
# readers. Missing native Work receipts remain unknown; these pins confer no
# W1, cost, lifecycle, Host or consensus qualification.
CONVERGENCE_REQUIRED_PATHS |= frozenset((
    "scripts/read_validated_business_goodput.py",
    "scripts/ci/test_read_validated_business_goodput.py",
))
# The current lifetime/semantics successors and their named completion gate are
# required review inputs. These pins cannot turn conditional arithmetic or a
# completed source-control roster into a cryptographic or service qualification.
CONVERGENCE_REQUIRED_PATHS |= frozenset((
    "scripts/w1_lifetime_ledger.py",
    "scripts/ci/test_w1_lifetime_ledger.py",
    "scripts/ci/w1_qrom_closure_controls.py",
    "scripts/ci/test_w1_qrom_closure_controls.py",
    "config/pon/w1-qrom-closure-required-tests-v1.json",
    ".github/workflows/pon-w1-qrom-closure.yml",
    "evidence/pon-w1-lifetime-current-20261109/project-input.json",
    "evidence/pon-w1-lifetime-current-20261109/project-report.json",
    "evidence/pon-w1-lifetime-current-20261109/README.md",
    "evidence/pon-w1-lifetime-current-20261111/project-input.json",
    "evidence/pon-w1-lifetime-current-20261111/project-report.json",
    "evidence/pon-w1-lifetime-current-20261111/README.md",
    "docs/security/W1_LIFETIME_AND_INDEPENDENT_ACCEPTANCE_20261107.md",
    "scripts/w1_qrom_semantics_audit.py",
    "scripts/ci/test_w1_qrom_semantics_audit.py",
    "evidence/pon-w1-qrom-semantics-20261107/report.json",
    "evidence/pon-w1-qrom-semantics-current-20261109/report.json",
    "evidence/pon-w1-qrom-semantics-current-20261109/README.md",
))
# Historical fixture controls must retain the original exact source contract.
# Their success does not accept the current worktree as that historical source.
CONVERGENCE_REQUIRED_PATHS |= frozenset((
    "scripts/w1_qrom_implementation_audit.py",
    "scripts/ci/test_w1_qrom_implementation_audit.py",
    "config/pon/w1-qrom-implementation-v1.json",
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

# Bind the native release owner, ordinary callers, and original fixture drivers.
M15_RELEASE_OWNER_REQUIRED_PATHS = frozenset((
    "scripts/m15_isolated_native_run.py",
    "scripts/m15_isolated_native_setup.py",
    "scripts/m15_isolated_native_support.py",
    "scripts/m15_native_build_support.py",
    "scripts/m15_static_native_build.py",
    "scripts/test_m15_native_fixture_tools.py",
    "trillionnium/crates/trnm-pon-node/Cargo.toml",
    "trillionnium/crates/trnm-pon-node/src/lib.rs",
    "trillionnium/crates/trnm-pon-node/src/main.rs",
    "trillionnium/crates/trnm-pon-node/src/operator_continuous_controller.rs",
    "trillionnium/crates/trnm-pon-node/src/operator_pq_m15_fixture_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/operator_pq_startup_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/bundle_wire.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/catalog.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/clock_contract.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/clock_contract_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/codec.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/consumer.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/deployment.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/elf.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/execution_wire.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/files.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/files_faults.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/files_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/frontier.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/frontier_service.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/launch.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/native_build_fixture.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/native_consumer_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/native_isolation_fixture.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/native_observation_fixture.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/native_provision_fixture.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/owner.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/process_identity.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/proof_state.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/proof_test_keys.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/proof_wire.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/protected.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/records.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/root_separation.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/root_separation_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/sealed.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/sealed_faults.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/sealed_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/service_clock.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/service_configuration.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/service_faults.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/service_socket.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/service_store.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/service_test_fixture.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/service_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/system_root.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/transaction.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/transaction_faults.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/transaction_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/trust_client.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/trust_wire.rs",
    "trillionnium/crates/trnm-pon-node/src/release_owner/unix_transport.rs",
))
NATIVE_REQUIRED_PATHS |= M15_RELEASE_OWNER_REQUIRED_PATHS
# Fixed source closure for the reviewed parent recovery and ordinary NPQ6 owner.
# This extends source integrity only; it is not native or deployment qualification.
NATIVE_REQUIRED_PATHS |= frozenset((
    "trillionnium/crates/trnm-pon-node/src/ingress/pq_network/recovery_request_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/pq_network/shared.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/shared_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/shared_tests/recovery_cases.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/shared_tests/recovery_cases/fixture.rs",
    "trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/shared_tests/recovery_cases/proxy.rs",
    "trillionnium/crates/trnm-pon-node/src/pq_parent_cli.rs",
    "trillionnium/crates/trnm-pon-node/src/pq_parent_cli/config.rs",
    "trillionnium/crates/trnm-pon-node/src/pq_parent_cli/config/npq6.rs",
    "trillionnium/crates/trnm-pon-node/src/pq_parent_cli/recovery.rs",
    "trillionnium/crates/trnm-pon-node/src/pq_parent_cli/service.rs",
    "trillionnium/crates/trnm-pon-node/src/pq_parent_cli/tests.rs",
    "trillionnium/crates/trnm-pon-node/src/public_submit.rs",
    "trillionnium/crates/trnm-pon-node/src/public_submit/pq.rs",
    "trillionnium/crates/trnm-pon-node/src/public_submit/pq/context_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/public_submit/pq/files.rs",
    "trillionnium/crates/trnm-pon-node/src/public_submit/pq/journal.rs",
    "trillionnium/crates/trnm-pon-node/src/public_submit/pq/journal_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/public_submit/pq/recovery.rs",
    "trillionnium/crates/trnm-pon-node/src/public_submit/pq/recovery/delivery.rs",
    "trillionnium/crates/trnm-pon-node/src/public_submit/pq/recovery/observations.rs",
    "trillionnium/crates/trnm-pon-node/tests/pq_parent_cli.rs",
    "trillionnium/crates/trnm-pon-node/tests/pq_parent_cli/support.rs",
    "trillionnium/crates/trnm-pon-node/tests/pq_parent_cli_feature_required.rs",
    "trillionnium/crates/trnm-pon-node/tests/pq_parent_npq6_cli.rs",
    "trillionnium/crates/trnm-pon-node/tests/pq_parent_npq6_cli/fixture.rs",
    "trillionnium/crates/trnm-pon-node/tests/pq_parent_npq6_cli/negative.rs",
))
NATIVE_REQUIRED_PATHS |= frozenset((
    "trillionnium/crates/trnm-pon-node/src/pq_application_local.rs",
    "trillionnium/crates/trnm-pon-node/src/pq_application_local/config.rs",
    "trillionnium/crates/trnm-pon-node/src/store/pq_existing_owner_tests.rs",
    "trillionnium/crates/trnm-pon-node/tests/pq_application_local_cli.rs",
    "trillionnium/crates/trnm-pon-node/tests/pq_application_local_cli/export.rs",
    "trillionnium/crates/trnm-pon-node/tests/pq_application_local_cli/fixture.rs",
    "trillionnium/crates/trnm-pon-node/tests/pq_application_local_cli/fixture/tasks.rs",
    "trillionnium/crates/trnm-pon-node/tests/pq_application_local_feature_off.rs",
))
# Complete storage owner closure. These are source-integrity requirements,
# not evidence of funded future custody, independent providers or FinalUse.
CELL_STORAGE_CONVERGENCE_REQUIRED_PATHS = frozenset((
    ".github/workflows/pon-next-architecture-security.yml",
    "docs/development/specs/pon/CELL_STORAGE_CONVERGENCE_DEV_V1.md",
    "evidence/cell-storage-convergence-f2568-20261109/controls/original-auth-server-tests.rs",
    "formal/pon-nakamoto-v1/vectors/cell-storage-owner-vectors-v1.json",
    "formal/pon-nakamoto-v1/vectors/cell-version-retention-v3.json",
    "scripts/cell_storage_descriptor_reference.py",
    "scripts/cell_version_retention_v3_vector.py",
    "scripts/ci/test_cell_storage_convergence_ci.py",
    "trillionnium/crates/trnm-data-availability/src/cell.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/discovery/pq.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/discovery/pq/auth.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/discovery/pq/auth_tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/erasure.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/erasure/provider.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/erasure/provider/admission.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/erasure/provider/contract.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/erasure/provider/tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/erasure/retained_plan.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/erasure/retained_plan/codec.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/erasure/retained_plan/file.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/host_handoff.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/host_handoff/tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/residency.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/residency/version.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/residency/version_tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/retention.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/retention/catalog_inventory.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/retention/payload_read.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/retention/payload_read/tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/snapshot_schedule.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/snapshot_schedule/tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/version_retention.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/version_retention/catalog.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/version_retention/codec.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/version_retention/inventory.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/version_retention/owner.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/version_retention/tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/version_retention/tests/residency.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/version_retention/tests/shard_plan.rs",
    "trillionnium/crates/trnm-pon-node/src/lib.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service/shard.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service/shard/plan.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service/shard_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service/tests.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service/version.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service/version_shard_plan_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service/version_tests.rs",
    "scripts/cell_sealed_bootstrap_v1.py",
    "scripts/llm_cell_sealed_worker_v1.py",
    "scripts/prepare_cell_sealed_research_v1.py",
    "scripts/test_llm_cell_sealed_worker_v1.py",
    "trillionnium/crates/trnm-data-availability/Cargo.toml",
    "trillionnium/crates/trnm-data-availability/examples/cell_sealed_research_next_use_v1.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/host_handoff/fd_handoff.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/host_handoff/tests/research_fds.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/version_retention/tests/shard_plan_capacity.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service/shard/plan/recovery.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service/shard/plan/recovery/execute.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service/version_shard_recovery_tests.rs",
))
NATIVE_REQUIRED_PATHS |= CELL_STORAGE_CONVERGENCE_REQUIRED_PATHS

# Native root components remain explicit research/HOLD dependencies.
NATIVE_REQUIRED_PATHS |= frozenset((
    "scripts/ci/run_pq_root_native_v3.py",
    "scripts/ci/test_run_pq_root_native_v3.py",
    "scripts/ci/pq_root_dependency_register.py",
    "scripts/ci/test_pq_root_dependency_register.py",
    "config/pon/pq-root-dependency-register-v3.json",
    "docs/security/PQ_ROOT_DEPENDENCY_REGISTER_V3.md",
    "docs/security/PQ_ROOT_RECOVERY_NATIVE_V3.md",
    "trillionnium/crates/trnm-crypto-primitives/src/pq_root_v3.rs",
    "trillionnium/crates/trnm-crypto-primitives/src/pq_root_v3/tests.rs",
    "trillionnium/crates/trnm-crypto-primitives/tests/pq_root_v3_native.rs",
    "trillionnium/crates/trnm-release-bundle/src/root_recovery_v3.rs",
    "trillionnium/crates/trnm-release-bundle/src/root_recovery_v3_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/root_recovery_v3.rs",
    "trillionnium/crates/trnm-pon-node/src/root_recovery_v3/anchor.rs",
    "trillionnium/crates/trnm-pon-node/src/root_recovery_v3/storage.rs",
    "trillionnium/crates/trnm-pon-node/tests/root_recovery_v3_native.rs",
))
NATIVE_FALSE = frozenset((
    "whole_native_authorization_migrated", "default_profile_migrated",
    "allow_legacy_fallback", "production_activation", "public_wan_accepted",
    "physical_rollback_resistant",
))

# New security observations require explicit source inventory entries even
# where their filenames are outside the automatically scanned PQ namespace.
NATIVE_REQUIRED_PATHS |= frozenset((
    "scripts/ci/check_consensus_roster.py",
    "scripts/ci/test_consensus_roster.py",
    "scripts/ci/run_pq_root_witness_v5.py",
    "scripts/ci/test_run_pq_root_witness_v5.py",
    "scripts/ci/ci_observation.py",
    "scripts/ci/test_ci_observation_process.py",
    "formal/pon-nakamoto-v1/bounded_process.py",
    "trillionnium/crates/trnm-pon-node/src/root_recovery_v3/witnessed_v5.rs",
    "trillionnium/crates/trnm-pon-node/tests/root_witness_v5_native.rs",
    "trillionnium/crates/trnm-pon-node/tests/root_witness_v5_durable_native.rs",
    "trillionnium/crates/trnm-pon-node/src/root_recovery_v3/witnessed_v5/durable.rs",
    "trillionnium/crates/trnm-pon-node/src/root_recovery_v3/witnessed_v5/provider_readback.rs",
    "trillionnium/crates/trnm-pon-node/tests/root_witness_provider_v5_native.rs",
    "trillionnium/crates/trnm-pon-node/tests/public_v3_distinct_invalid_work.rs",
    "docs/security/ROOT_WITNESS_V5.md",
    "evidence/pon-w1-lifetime-current-20261111/README.md",
    "evidence/pon-w1-lifetime-current-20261111/project-input.json",
    "evidence/pon-w1-lifetime-current-20261111/project-report.json",
))

# The convergence adds executable scope and historical/current separation.
# Presence and pins remain source consistency, not whole-chain qualification.
NATIVE_REQUIRED_PATHS |= frozenset((
    "scripts/w1_qrom_historical_fixture.py",
    "scripts/ci/w1_qrom_supplemental_controls.py",
    "config/pon/w1-qrom-supplemental-tests-v1.json",
    "evidence/pq-chain-convergence-20261111-d4d2/README.md",
    "evidence/pq-chain-convergence-20261111-d4d2/lifetime-input.json",
    "evidence/pq-chain-convergence-20261111-d4d2/lifetime-report.json",
    "evidence/pq-live-retry-20261111-fa62381e/lifetime-input.json",
    "evidence/pq-live-retry-20261111-fa62381e/lifetime-report.json",
    "scripts/ci/test_w1_qrom_historical_fixture.py",
    "trillionnium/crates/trnm-mvcc-fee/tests/account_development_scope.rs",
    "trillionnium/crates/trnm-pon-node/src/store/account_profile_scope_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/store/operator_continuous_owner.rs",
    "trillionnium/crates/trnm-pon-node/src/store/operator_mining_owner.rs",
    "docs/security/ACCOUNT_AUTHORIZATION_DEVELOPMENT_BOUNDARY_20261110.md",
))


# Current upstream withdrawal and finite posterior calculations must not evade
# inventory merely because their names do not start with the PQ prefix.
# Selected V6 owner and policy inputs require explicit pins even without PQ
# names. This slice is source integrity, not the full dependency closure or
# qualification of the source attribution and valuation model.
NATIVE_REQUIRED_PATHS |= frozenset((
    "config/pon/model-source-composition-v6.json",
    "config/pon/public-evaluation-model-source-composition-v6.json",
    "config/pon/model-evidence-v3.json",
    "trillionnium/crates/trnm-mvcc-fee/src/model_source_composition_v6.rs",
    "trillionnium/crates/trnm-mvcc-fee/src/model_evidence_v3.rs",
    "trillionnium/crates/trnm-pon-node/tests/model_source_composition_v6.rs",
))

# Current upstream withdrawal must remain in the original required inventory.
# Source consistency does not approve migrated proofs or current use.
NATIVE_REQUIRED_PATHS |= frozenset((
    "config/pon/w1-upstream-security-v1.json",
    "scripts/ci/w1_upstream_security.py",
    "scripts/ci/test_w1_upstream_security.py",
    "formal/pon-nakamoto-v1/quantum_posterior_policy.py",
    "formal/pon-nakamoto-v1/test_quantum_posterior_policy.py",
    "formal/pon-nakamoto-v1/test_quantum_resource_clock.py",
    "formal/pon-nakamoto-v1/QUANTUM_POSTERIOR_POLICY_V1.md",
    "evidence/pon-quantum-lifetime-20261111-e464/README.md",
    "evidence/pon-quantum-lifetime-20261111-e464/resource-model-counterexample.json",
    "evidence/pon-quantum-lifetime-20261111-e464/lifetime-input.json",
    "evidence/pon-quantum-lifetime-20261111-e464/lifetime-report.json",
    "evidence/pon-quantum-lifetime-20261111-e464/upstream-security-report.json",
    "evidence/pon-quantum-lifetime-20261111-e464/proof-profile-binding-report.json",
    "evidence/pon-quantum-lifetime-20261111-e464/persistent-request.json",
    "evidence/pon-quantum-lifetime-20261111-e464/persistent-report.json",
    "evidence/pon-quantum-lifetime-20261111-e464/refresh-request.json",
    "evidence/pon-quantum-lifetime-20261111-e464/refresh-report.json",
))

# Account scope and durable retry provenance controls remain distinct from the
# original 52-control PNQ2/PqWitnessV4 roster and its historical observations.
NATIVE_REQUIRED_PATHS |= frozenset((
    "config/pon/pq-system-supplemental-tests-v1.json",
    "trillionnium/crates/trnm-pon-node/src/ingress/account_scope_tests.rs",
))

# V4 continuation inputs are mandatory source dependencies, not proof of
# independently deployed custody, external effects or algorithm migration.
NATIVE_REQUIRED_PATHS |= frozenset((
    "scripts/ci/run_pq_root_continuation_v4.py",
    "scripts/ci/test_run_pq_root_continuation_v4.py",
    "scripts/ci/test_authenticated_suite_count.py",
    "scripts/ci/pq_root_custody_review_v1.py",
    "scripts/ci/test_pq_root_custody_review_v1.py",
    "scripts/ci/pq_root_custody_review_v2.py",
    "scripts/ci/test_pq_root_custody_review_v2.py",
    "scripts/ci/pq_root_migration_review_v1.py",
    "scripts/ci/test_pq_root_migration_review_v1.py",
    "config/pon/pq-root-custody-review-v1.json",
    "config/pon/pq-root-custody-review-v2.json",
    "config/pon/pq-root-migration-review-v1.json",
    "docs/security/PQ_ROOT_RECOVERY_FLOOR_V4.md",
    "docs/security/PQ_ROOT_CUSTODY_REVIEW_V2.md",
    "docs/security/SYSTEM_BOUNDARY_QUALIFICATION_20261109.md",
    "docs/security/PQ_ROOT_EFFECT_READBACK_NATIVE_V4.md",
    "docs/security/PQ_ROOT_MIGRATION_REVIEW_V1.md",
    "trillionnium/crates/trnm-pon-node/src/root_recovery_v3/recovery_floor.rs",
    "trillionnium/crates/trnm-pon-node/src/root_recovery_v3/effect_readback_v4.rs",
    "trillionnium/crates/trnm-pon-node/tests/recovery_floor_v4_native.rs",
    "trillionnium/crates/trnm-pon-node/tests/root_effect_readback_v4_native.rs",
    "trillionnium/crates/trnm-pon-node/tests/root_budget_v4_native.rs",
    "trillionnium/crates/trnm-pon-node/tests/support/root_recovery_v3_fixture.rs",
))

# Complete declared content graphs and finite genesis-to-checkpoint state
# histories are separate readback formats. Their mandatory source presence is
# not loader completeness, historical provenance or migration authorization.
NATIVE_REQUIRED_PATHS |= frozenset((
    "docs/security/CONTENT_GRAPH_AND_HISTORY_READBACK_V1.md",
    "scripts/ci/check_cell_content_graph_vectors_v3.py",
    "tests/fixtures/cell-content-graph-v3/vectors.json",
    "trillionnium/crates/trnm-data-availability/src/cell/content_graph_v3.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/content_graph_v3/tests.rs",
    "trillionnium/crates/trnm-mvcc-fee/src/content_commitment_v1/history_v2.rs",
    "trillionnium/crates/trnm-mvcc-fee/src/content_commitment_v1/history_v2/tests.rs",
    "trillionnium/crates/trnm-pon-node/src/store/migration_history_v2.rs",
    "trillionnium/crates/trnm-pon-node/src/store/migration_history_v2/tests.rs",
))

# Preserve complete original observations and recovery refusals as source bytes.
# Mandatory presence is not native execution or security/authority acceptance.
NATIVE_REQUIRED_PATHS |= frozenset((
    "evidence/hash-content-closure-20261111-976f/README.md",
    "evidence/hash-content-closure-20261111-976f/ai395-b-all-features-metadata-compact.json",
    "evidence/hash-content-closure-20261111-976f/ai395-b-all-features-metadata-members.json",
    "evidence/hash-content-closure-20261111-976f/ai395-b-all-features-metadata.tar.gz",
    "evidence/hash-content-closure-20261111-976f/ai395-b-native-members.json",
    "evidence/hash-content-closure-20261111-976f/ai395-b-native-observations.tar.xz",
    "evidence/hash-content-closure-20261111-976f/ai395-b-native-summary.json",
    "evidence/hash-content-closure-20261111-976f/ai395-b-python16-controls-compact.json",
    "evidence/hash-content-closure-20261111-976f/ai395-b-python16-controls-members.json",
    "evidence/hash-content-closure-20261111-976f/ai395-b-python16-controls.tar.gz",
    "evidence/hash-content-closure-20261111-976f/cloud-b-observations-976f.archive.json",
    "evidence/hash-content-closure-20261111-976f/cloud-b-observations-976f.tar.gz",
    "evidence/hash-content-closure-20261111-976f/final-b-hash-purpose-preservation-review.json",
    "evidence/hash-content-closure-20261111-976f/mac-pr927-body-update-public-summary.json",
    "evidence/hash-content-closure-20261111-976f/mac-publication-public-summary-976f.json",
    "evidence/hash-content-closure-20261111-976f/recovery-observations.tar.xz",
    "evidence/hash-content-closure-20261111-976f/staging-manifest.json",
    "evidence/hash-content-closure-20261111-976f/unpublished-cloud-c-observation.json",
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


# Explicit selected-source coverage for the V6 settlement / joint DAA composition.
# These byte records do not qualify incentives, consensus, resources or production.
ECONOMICS_INTEGRATION_REQUIRED_PATHS = frozenset((
    "config/pon/joint-consensus-qualification-v1.json",
    "docs/development/INCENTIVE_LIABILITY_BOUNDARIES_20261112.md",
    "docs/development/SOURCE_INCENTIVE_RESEARCH_CONTRACT_20261112.md",
    "docs/protocol/pon-nakamoto-v1/details/CREDIT_CALIBRATION_DISTORTION_V1.md",
    "docs/protocol/pon-nakamoto-v1/details/DYNAMIC_PARTICIPATION_V1.md",
    "docs/protocol/pon-nakamoto-v1/details/JOINT_CONSENSUS_DAA_AUDIT_20261108.md",
    "docs/protocol/pon-nakamoto-v1/details/JOINT_CONSENSUS_QUALIFICATION_V1.md",
    "docs/protocol/pon-nakamoto-v1/details/JOINT_PRODUCTION_TAIL_V1.md",
    "formal/pon-nakamoto-v1/README.md",
    "formal/pon-nakamoto-v1/contracts/work-time-required-tests-v1.json",
    "formal/pon-nakamoto-v1/dynamic_participation_v1.py",
    "formal/pon-nakamoto-v1/experiments/joint_resource_competition_campaign.py",
    "formal/pon-nakamoto-v1/experiments/quantum_adversarial_campaign.py",
    "formal/pon-nakamoto-v1/experiments/quantum_network_campaign.py",
    "formal/pon-nakamoto-v1/experiments/quantum_resource_clock_campaign.py",
    "formal/pon-nakamoto-v1/experiments/w1_marked_domain_campaign.py",
    "formal/pon-nakamoto-v1/joint_consensus_qualification.py",
    "formal/pon-nakamoto-v1/joint_production_tail_v1.py",
    "formal/pon-nakamoto-v1/native_risk_ledger.py",
    "formal/pon-nakamoto-v1/quantum_adversarial_search.py",
    "formal/pon-nakamoto-v1/quantum_network_sim.py",
    "formal/pon-nakamoto-v1/test_branch_time_daa_v1.py",
    "formal/pon-nakamoto-v1/test_dynamic_participation_v1.py",
    "formal/pon-nakamoto-v1/test_joint_consensus_qualification.py",
    "formal/pon-nakamoto-v1/test_joint_production_tail_v1.py",
    "formal/pon-nakamoto-v1/test_joint_resource_competition_campaign.py",
    "formal/pon-nakamoto-v1/test_native_risk_ledger.py",
    "formal/pon-nakamoto-v1/test_quantum_network_sim.py",
    "formal/pon-nakamoto-v1/test_quantum_probability_sampling.py",
    "formal/pon-nakamoto-v1/w1_marked_domain.py",
    "scripts/ci/test_pon_monotone_daa_reader.py",
    "scripts/pon_monotone_daa_reader.py",
    "trillionnium/crates/trnm-pon-node/tests/daa_joint_consensus.rs",
    "trillionnium/crates/trnm-task-kernel/src/tests.rs",
))
NATIVE_REQUIRED_PATHS |= ECONOMICS_INTEGRATION_REQUIRED_PATHS


# Preserve complete inputs of the independently retained research components.
NATIVE_REQUIRED_PATHS |= frozenset(('config/pon/pq128-lifetime-composition-v2.json',
 'docs/research/W1_ORACLE_EVIDENCE_SCOPE_V1.md',
 'docs/security/PQ128_LIFETIME_COMPOSITION_V2.md',
 'docs/security/PQ_CONTENT_CHAIN_REVIEW_V1.md',
 'docs/security/RETAINED_RESEARCH_COMPONENTS_20261113.md',
 'docs/security/W1_P3_SAMPLING_CONDITIONAL_ACCOUNTING.md',
 'docs/security/W1_RISC0_DEEP_NAMED_EVENTS.md',
 'formal/pon-nakamoto-v1/COST_TAIL_TRANSFER_V1.md',
 'formal/pon-nakamoto-v1/FIXED_SUCCESS_QUERY_FRONTIER_V1.md',
 'formal/pon-nakamoto-v1/QUANTUM_BERNOULLI_SOURCE_AUDIT_V1.md',
 'formal/pon-nakamoto-v1/cost_tail_transfer.py',
 'formal/pon-nakamoto-v1/fixed_success_query_frontier.py',
 'formal/pon-nakamoto-v1/quantum_bernoulli_source_audit.py',
 'formal/pon-nakamoto-v1/test_cost_tail_transfer.py',
 'formal/pon-nakamoto-v1/test_fixed_success_query_frontier.py',
 'formal/pon-nakamoto-v1/test_quantum_bernoulli_source_audit.py',
 'formal/pon-nakamoto-v1/test_w1_quantum_evidence_scope.py',
 'formal/pon-nakamoto-v1/test_w1_quantum_native_bridge.py',
 'formal/pon-nakamoto-v1/w1_public_stark_research/Cargo.lock',
 'formal/pon-nakamoto-v1/w1_public_stark_research/security_model_audit/vendor_primary/p3-challenger-0.8.0.crate',
 'formal/pon-nakamoto-v1/w1_public_stark_research/security_model_audit/vendor_primary/p3-fri-0.8.0.crate',
 'formal/pon-nakamoto-v1/w1_quantum_evidence_scope.py',
 'formal/pon-nakamoto-v1/w1_quantum_native_bridge.py',
 'scripts/ci/pq_content_chain_review.py',
 'scripts/ci/pq_lifetime_composition.py',
 'scripts/ci/test_pq_content_chain_review.py',
 'scripts/ci/test_pq_lifetime_composition.py',
 'scripts/ci/test_retained_research_ci.py',
 'scripts/ci/test_w1_p3_sampling_audit.py',
 'scripts/ci/test_w1_risc0_deep_event_audit.py',
 'scripts/w1_p3_sampling_audit.py',
 'scripts/w1_risc0_deep_event_audit.py'))

# Explicitly retain the reviewed consolidation controls.
# These source pins do not grant runtime or production qualification.
CONSOLIDATION_CONTROL_REQUIRED_PATHS = frozenset((
    "scripts/read_failed_native_campaign_zip.py",
    "scripts/ci/test_read_failed_native_campaign_zip.py",
    "scripts/pon_public_v3_phase_read.py",
    "scripts/ci/test_pon_public_v3_phase_read.py",
    'config/pon/decentralization-audit-v1.json',
    'docs/protocol/pon-nakamoto-v1/details/WAN_EVIDENCE_ACCOUNTING_V1.md',
    'scripts/ci/fixtures/pon_decentralization_v1.json',
    'scripts/ci/test_pon_decentralization_audit.py',
    'scripts/ci/test_pon_wan_control_domains.py',
    'scripts/ci/test_pon_wan_evidence.py',
    'scripts/pon_decentralization_audit.py',
    'scripts/pon_wan_evidence.py',
    "scripts/ci/chain_system_security.py",
    "scripts/ci/test_chain_system_security.py",
    "scripts/ci/pq_external_rollback_oracle.py",
    "scripts/ci/test_pq_external_rollback_oracle.py",
    "scripts/pon_w1_false_trace_reuse_reader_v1.py",
    "scripts/ci/test_pon_w1_false_trace_reuse_reader_v1.py",
    "scripts/llm_runtime_trial_ledger.py",
    "scripts/test_llm_runtime_trial_ledger.py",
    "formal/pon-native-fullpath-v1/collect_native.py",
    "formal/pon-native-fullpath-v1/test_collect_native.py",
    "formal/release-finality-v2/control_domains.py",
    "formal/release-finality-v2/test_control_domains.py",
    "formal/release-finality-v2/campaign_gate.py",
    "docs/security/SYSTEM_SECURITY_BLOCKERS_V1.md",
    "trillionnium/crates/trnm-pon-node/src/account_archive_prototype/packed_branch_regression_tests.rs",
    "trillionnium/crates/trnm-pon-node/tests/account_archive_prototype.rs",
    "formal/pon-nakamoto-v1/test_pq_sqlite_schema_names.py",
))
# Bind the reviewed peer owner pre-write and occupied-endpoint controls.
# These source requirements do not activate the local service or qualify PQ.
CONSOLIDATION_CONTROL_REQUIRED_PATHS |= frozenset((
    "trillionnium/crates/trnm-peer-lease/src/payload_body.rs",
    "trillionnium/crates/trnm-peer-lease/src/payload_recovery/part_02_owner.rs",
    "trillionnium/crates/trnm-peer-lease/src/unix.rs",
    "trillionnium/crates/trnm-peer-lease/src/unix/connection_service.rs",
))
# Retain Q4 advisory source and its original native reentry control.
# Source coverage neither signs a renewal nor grants admission authority.
CONSOLIDATION_CONTROL_REQUIRED_PATHS |= frozenset((
    "trillionnium/crates/trnm-pon-node/src/operator_continuous_lease.rs",
    "trillionnium/crates/trnm-pon-node/src/operator_continuous_lease_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/lib.rs",
    "trillionnium/crates/trnm-pon-node/src/store.rs",
    "trillionnium/crates/trnm-pon-node/tests/continuity_authenticated.rs",
))
NATIVE_REQUIRED_PATHS |= CONSOLIDATION_CONTROL_REQUIRED_PATHS

# Exact reviewed Cell source coverage; no execution or acceptance is inferred.
CELL_REVIEWED_PAGED_REQUIRED_PATHS = frozenset((
    "docs/development/specs/pon/CELL_SEALED_PAGED_RESEARCH_NEXT_USE_V1.md",
    "trillionnium/crates/trnm-data-availability/examples/cell_sealed_research_next_use_v2.rs",
    "trillionnium/crates/trnm-data-availability/examples/cell_sealed_research_paged_next_use_v1.rs",
    "trillionnium/crates/trnm-data-availability/examples/cell_sealed_research_v2/bep52.rs",
    "trillionnium/crates/trnm-data-availability/examples/cell_sealed_research_v2/paged.rs",
    "trillionnium/crates/trnm-data-availability/examples/cell_sealed_research_v2/paged/tests.rs",
    "trillionnium/crates/trnm-data-availability/examples/cell_sealed_research_v2/snapshot.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/bep52_peer/release.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/bep52_peer/release/tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/bep52_storage.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/bep52_storage/peer.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/bep52_storage/peer/tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/bep52_storage/tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/erasure/retained_plan/paged.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/erasure/retained_plan/paged/codec.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/erasure/retained_plan/paged/file.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/erasure/retained_plan/paged/restore.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/erasure/retained_plan/paged/restore/tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/release_snapshot.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/release_snapshot/tests.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/retention/reservation_preflight.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/version_retention/chunk_read.rs",
    "trillionnium/crates/trnm-data-availability/src/cell/version_retention/tests/shard_plan_paged.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service/shard/plan/paged.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service/shard/plan/paged/recovery.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service/shard/plan/paged/recovery/execute.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service/shard/plan/paged/recovery/preflight.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service/version_paged_shard_plan_tests.rs",
    "trillionnium/crates/trnm-pon-node/src/store/storage_service/version_paged_shard_recovery_tests.rs",
))
NATIVE_REQUIRED_PATHS |= CELL_REVIEWED_PAGED_REQUIRED_PATHS

# Lossless retention, named native completion, and fresh rejection readers
# are required source dependencies. Pins do not authenticate reported clocks
# or grant native execution, resource-cost, or security qualification.
NATIVE_OBSERVATION_REQUIRED_PATHS = frozenset((
    "scripts/ci/prepare_artifact_upload.py",
    "scripts/ci/test_prepare_artifact_upload.py",
    "scripts/ci/w1_native_controls.py",
    "scripts/ci/test_w1_factorial_native_gate.py",
    "scripts/ci/check_w1_native_roster.py",
    "scripts/ci/test_w1_native_roster.py",
    "scripts/ci/w1_native_rosters_v1.json",
    "scripts/pon_fresh_rejection_report.py",
    "scripts/ci/test_fresh_rejection_report.py",
))
NATIVE_REQUIRED_PATHS |= NATIVE_OBSERVATION_REQUIRED_PATHS

# Public-fixture admission research remains separate from current owner/effect
# authority. Preserve the exact reusable bridge and its original-control map.
SP27_03_RESEARCH_REQUIRED_PATHS = frozenset((
    "docs/security/SP27_03_RESEARCH_BRIDGE_RETAINED_V1.md",
    "trillionnium/crates/trnm-research-protocol/examples/sp27_03_authorization_adapter.rs",
))
NATIVE_REQUIRED_PATHS |= SP27_03_RESEARCH_REQUIRED_PATHS


def is_pq_source(parts: tuple[str, ...]) -> bool:
    """Recognize versioned pq3 modules, pq.rs, cell_pq and older prefixes."""
    return any(
        part.startswith(("pq_", "pqg_", "pql"))
        or re.search(r"(?:^|_)pq(?:[0-9]+)?(?:_|$)", Path(part).stem)
        for part in parts
    )

# Explicit closure for the reviewed endpoint and library ports. Presence is
# source integrity only; it grants no cryptographic or network qualification.
CONSOLIDATED_ENDPOINT_REQUIRED_PATHS = frozenset((
    'config/pon/pq-native-tls-endpoint-required-tests-v1.json',
    'docs/security/PQ_TLS_PINNED_ENDPOINT_V1.md',
    'trillionnium/crates/trnm-data-availability/src/cell/bep52_peer/dht/lookup.rs',
    'trillionnium/crates/trnm-data-availability/src/cell/bep52_peer/dht/lookup/tests.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/pq_network.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/shared.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/context.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/diagnostics.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/endpoint_tests.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/io.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/io/buffer_tests.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/tests.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls_endpoint.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls_profile.rs',
    'trillionnium/crates/trnm-pon-node/src/pq_tls_cli.rs',
    'trillionnium/crates/trnm-pon-node/src/store.rs',
    'trillionnium/crates/trnm-pon-node/src/store/confirmation_chainwork_tests.rs',
    'trillionnium/crates/trnm-pon-node/src/store/pq_network.rs',
    'trillionnium/crates/trnm-pon-node/tests/pq_tls_endpoint_cli.rs',
    'trillionnium/crates/trnm-pon-node/tests/pq_tls_refusal_diagnostics.rs',
    'trillionnium/crates/trnm-pon-node/tests/pq_tls_witness_cli/refusal_diagnostics.rs',
    'trillionnium/crates/trnm-pon-node/tests/pq_tls_witness_cli/support.rs',
))
NATIVE_REQUIRED_PATHS |= CONSOLIDATED_ENDPOINT_REQUIRED_PATHS


# Reviewed opt-in positive-product facts, prior SQLite growth reservations,
# and bounded runtime cache assembly retain their exact source closure.
# Source coverage does not select these APIs or certify runtime authority.
CONSOLIDATED_LIBRARY_REQUIRED_PATHS = frozenset((
    'trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs',
    'trillionnium/crates/trnm-crypto-primitives/src/pon_work/task_product_facts.rs',
    'trillionnium/crates/trnm-crypto-primitives/src/pon_work/task_product_facts/tests.rs',
    'trillionnium/crates/trnm-data-availability/src/cell.rs',
    'trillionnium/crates/trnm-data-availability/src/cell/runtime_root.rs',
    'trillionnium/crates/trnm-data-availability/src/cell/runtime_root_tests.rs',
    'trillionnium/crates/trnm-data-availability/src/cell/store.rs',
    'trillionnium/crates/trnm-sqlite-io-boundary/src/ledger.rs',
    'trillionnium/crates/trnm-sqlite-io-boundary/src/lib.rs',
    'trillionnium/crates/trnm-sqlite-io-boundary/src/owner.rs',
    'trillionnium/crates/trnm-sqlite-io-boundary/src/reservation_v2_tests.rs',
    'trillionnium/crates/trnm-sqlite-io-boundary/src/unsupported.rs',
    'trillionnium/crates/trnm-sqlite-io-boundary/src/vfs.rs',
))
NATIVE_REQUIRED_PATHS |= CONSOLIDATED_LIBRARY_REQUIRED_PATHS


# Explicit SP27 research selectors retain the original Host, phase windows,
# named controls and complete failure denominators. Source presence is never
# collection success, business confirmation, or a qualification decision.
SP27_RESEARCH_REQUIRED_PATHS = frozenset((
    'scripts/ci/run_from_zero_host.py',
    'scripts/ci/run_from_zero_native.py',
    'scripts/ci/run_sp27_receiver_controls.py',
    'scripts/ci/run_sp27_strata_controls.py',
    'scripts/ci/test_run_from_zero_native.py',
    'scripts/ci/test_sp27_receiver_controls.py',
    'scripts/ci/test_sp27_strata_controls.py',
    'trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero.rs',
    'trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero/sp27_receiver_campaign.rs',
    'trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero/sp27_receiver_controls.rs',
    'trillionnium/crates/trnm-pon-node/tests/public_v3_from_zero/sp27_receiver_strata.rs',
))
NATIVE_REQUIRED_PATHS |= SP27_RESEARCH_REQUIRED_PATHS



# Audited reusable components; source integrity never implies activation.
NATIVE_REQUIRED_PATHS |= frozenset((
    'trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs',
    'trillionnium/crates/trnm-mvcc-fee/src/checkpoint_tile_material_v1.rs',
    'trillionnium/crates/trnm-mvcc-fee/tests/checkpoint_tile_material_v1.rs',
    'trillionnium/crates/trnm-pon-node/tests/public_v3_paid_cpu_debt_recovery.rs',
))


# Audited reusable components; source integrity never implies activation.
NATIVE_REQUIRED_PATHS |= frozenset((
    'scripts/ci/pq_external_rollback_oracle.py',
    'scripts/ci/test_pq_external_rollback_oracle.py',
))

# Immutable expansion and independent legal producer closure.
NATIVE_REQUIRED_PATHS |= frozenset((
    'trillionnium/crates/trnm-crypto-primitives/src/pq_root_v3.rs',
    'trillionnium/crates/trnm-crypto-primitives/src/pq_root_v3/tests.rs',
    'trillionnium/crates/trnm-crypto-primitives/tests/pq_root_v3_native.rs',
    'trillionnium/crates/trnm-crypto-primitives/examples/pq_root_v3_cost_observation.rs',
    'docs/security/PQ_ROOT_SIGNATURE_COST_V1.md',
    'trillionnium/crates/trnm-crypto-primitives/Cargo.toml',
    'trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs',
    'trillionnium/crates/trnm-crypto-primitives/src/pon_work/low_rank_prefix.rs',
    'trillionnium/crates/trnm-crypto-primitives/src/pon_work/legal_attempt.rs',
    'trillionnium/crates/trnm-crypto-primitives/examples/pon_w1_rank_batch_v5.rs',
    'scripts/ci/run_pq_root_native_v3.py',
    'scripts/ci/test_run_pq_root_native_v3.py',
    'scripts/ci/pq_root_dependency_register.py',
    'docs/security/PQ_ROOT_DEPENDENCY_REGISTER_V3.md',
    'docs/security/PQ_ROOT_RECOVERY_NATIVE_V3.md',
))

# Native cheap refusal and cross-claim journal readback remain required.
NATIVE_REQUIRED_PATHS |= frozenset((
    'trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs',
    'trillionnium/crates/trnm-crypto-primitives/src/pon_work/rejection_cache.rs',
    'trillionnium/crates/trnm-crypto-primitives/src/pon_work/rejection_cache_tests.rs',
    'trillionnium/crates/trnm-service-settlement/src/native_budget/task_operation_v2/tests.rs',
))


# Original bounded journal and native no-gain payment controls remain required.
NATIVE_REQUIRED_PATHS |= frozenset((
    'trillionnium/crates/trnm-worker-agent/src/tests.rs',
    'trillionnium/crates/trnm-pon-node/src/store/funding/tests.rs',
))

# The independent outbound journal preserves original wire/deadline ownership.
# Source inclusion is not whole-node or physical rollback qualification.
DURABLE_PQ_OUTBOUND_REQUIRED_PATHS = frozenset((
    'trillionnium/crates/trnm-pon-node/src/ingress/pq_network.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/outbound.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/outbound/tests.rs',
    'docs/security/PQ_DURABLE_OUTBOUND_V1.md',
))
NATIVE_REQUIRED_PATHS |= DURABLE_PQ_OUTBOUND_REQUIRED_PATHS


# Explicit final artifact, sealed descriptor and Q4 source controls.
NATIVE_REQUIRED_PATHS |= frozenset((
    'trillionnium/crates/trnm-worker-agent/src/audit.rs',
    'trillionnium/crates/trnm-worker-agent/src/audit/artifact.rs',
    'trillionnium/crates/trnm-pon-node/src/release_owner/sealed.rs',
    'trillionnium/crates/trnm-pon-node/src/release_owner/sealed_tests.rs',
    'trillionnium/crates/trnm-mvcc-fee/tests/qualified_task_lifecycle_v4.rs',
    'trillionnium/crates/trnm-pon-node/src/continuity_tests.rs',
))

# Independently reviewed final merge capabilities retain exact source coverage.
FINAL_REVIEWED_BRANCH_REQUIRED_PATHS = frozenset((
    '.github/workflows/pon-recent-batch-acceptance.yml',
    'config/pon/applicability-v1.json',
    'config/pon/public-resource-profile-vectors-v1.json',
    'docs/development/TRNM_PUBLIC_CALLER_GRANTS_R20_20261114.md',
    'docs/security/PQ_DURABLE_OUTBOUND_V1.md',
    'formal/pon-nakamoto-v1/q4_reference_go/q4-reference-development-vector.json',
    'formal/pon-native-fullpath-v1/collect_native.py',
    'formal/pon-native-fullpath-v1/test_collect_native.py',
    'formal/release-finality-v2/campaign_gate.py',
    'formal/release-finality-v2/control_domains.py',
    'formal/release-finality-v2/test_control_domains.py',
    'scripts/ci/test_pon_public_v3_policy_read.py',
    'scripts/ci/test_pon_w1_false_trace_reuse_reader_v1.py',
    'scripts/llm_neural_read_worker.py',
    'scripts/llm_runtime_pilot.py',
    'scripts/llm_runtime_trial_ledger.py',
    'scripts/pon_public_v3_policy_read.py',
    'scripts/pon_w1_false_trace_reuse_reader_v1.py',
    'scripts/prepare_cell_sealed_research_v1.py',
    'scripts/test_llm_cell_sealed_worker_v1.py',
    'scripts/test_llm_material_runtime_bridge.py',
    'scripts/test_llm_runtime_trial_ledger.py',
    'trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2.rs',
    'trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/tests.rs',
    'trillionnium/crates/trnm-mvcc-fee/tests/qualified_task_lifecycle_v4.rs',
    'trillionnium/crates/trnm-peer-lease/src/payload_body.rs',
    'trillionnium/crates/trnm-peer-lease/src/payload_recovery/part_02_owner.rs',
    'trillionnium/crates/trnm-peer-lease/src/unix.rs',
    'trillionnium/crates/trnm-peer-lease/src/unix/connection_service.rs',
    'trillionnium/crates/trnm-pon-node/src/continuity_tests.rs',
    'trillionnium/crates/trnm-pon-node/src/error.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/history_import_tests.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/pq_network.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/outbound.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/outbound/tests.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/public_v3/caller_grant_tests.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/public_v3/canonical_packet/tests.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/public_v3/intake.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/public_v3/work_arithmetic/tests.rs',
    'trillionnium/crates/trnm-pon-node/src/lib.rs',
    'trillionnium/crates/trnm-pon-node/src/operator_continuous_lease.rs',
    'trillionnium/crates/trnm-pon-node/src/operator_continuous_lease_tests.rs',
    'trillionnium/crates/trnm-pon-node/src/release_owner/sealed.rs',
    'trillionnium/crates/trnm-pon-node/src/release_owner/sealed_tests.rs',
    'trillionnium/crates/trnm-pon-node/src/store.rs',
    'trillionnium/crates/trnm-pon-node/src/store/reverse_path.rs',
    'trillionnium/crates/trnm-pon-node/tests/continuity_authenticated.rs',
    'trillionnium/crates/trnm-pon-node/tests/native_node.rs',
    'trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs',
    'trillionnium/crates/trnm-pon-node/tests/task_lifecycle_v4.rs',
    'trillionnium/crates/trnm-worker-agent/src/audit.rs',
    'trillionnium/crates/trnm-worker-agent/src/audit/artifact.rs',
))
NATIVE_REQUIRED_PATHS |= FINAL_REVIEWED_BRANCH_REQUIRED_PATHS


# Reviewed scheduling preserves existing absolute deadlines and r20 authority.
# These two paths are source identities, not a confirmation-latency claim.
PUBLIC_V3_REACTOR_REQUIRED_PATHS = frozenset((
    'trillionnium/crates/trnm-pon-node/src/ingress/public_v3.rs',
    'trillionnium/crates/trnm-pon-node/src/ingress/public_v3/input_decode_tests.rs',
))
NATIVE_REQUIRED_PATHS |= PUBLIC_V3_REACTOR_REQUIRED_PATHS


# Exact SQLite qualification reader and actual caller; controls alone grant no qualification.
SQLITE_REQUALIFICATION_READER_REQUIRED_PATHS = frozenset((
    'scripts/ci/check_sqlite_build_requalification.py',
    'scripts/ci/test_sqlite_build_requalification.py',
    '.github/workflows/pon-pq-system-continuation.yml',
    'scripts/ci/ci_job.sh',
))
NATIVE_REQUIRED_PATHS |= SQLITE_REQUALIFICATION_READER_REQUIRED_PATHS


# A non-atomic cgroup observation is not a Host capability or an effective quota proof.
CURRENT_CGROUP_OBSERVATION_REQUIRED_PATHS = frozenset((
    'scripts/ci/public_host_ci_observation.py',
    'scripts/ci/run_w1_rank_batch_v5.py',
    'scripts/ci/test_run_w1_rank_batch_v5.py',
))
NATIVE_REQUIRED_PATHS |= CURRENT_CGROUP_OBSERVATION_REQUIRED_PATHS


class IntegrityError(ValueError):
    pass


def _safe_regular(root: Path, relative: str, ceiling: int = 4 * 1024 * 1024) -> bytes:
    try:
        return read_regular(root, relative, ceiling)
    except SourceReadError as error:
        raise IntegrityError(str(error)) from error


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
    # Keep the caller's pathname so descriptor traversal can reject symlinked
    # checkout ancestors instead of silently selecting their resolved target.
    root = Path(root).absolute()
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
