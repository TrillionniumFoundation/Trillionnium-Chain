#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT
mkdir -p "${work_dir}/src"

types_path="${repo_root}/trillionnium/crates/trnm-consensus-types"
core_path="${repo_root}/trillionnium/crates/trnm-consensus-core"
cat >"${work_dir}/Cargo.toml" <<EOF
[package]
name = "trnm-a22-inert-capability-compile-fail"
version = "0.0.0"
edition = "2021"
publish = false

[workspace]

[dependencies]
trnm-consensus-types = { path = "${types_path}" }
trnm-consensus-core = { path = "${core_path}" }
EOF

cat >"${work_dir}/src/lib.rs" <<'RS'
use trnm_consensus_core::Core;
use trnm_consensus_types::{
    GenesisQcV0, VerifiedCometStateExportV1, VerifiedPocoTargetGenesisCeremonyV1,
    VerifiedPocoTargetProjectionV1,
};

pub fn type_visibility_baseline(
    _: Option<Core>,
    _: Option<GenesisQcV0>,
    _: Option<VerifiedCometStateExportV1>,
    _: Option<VerifiedPocoTargetProjectionV1>,
    _: Option<VerifiedPocoTargetGenesisCeremonyV1>,
) {
}
RS

cargo check --quiet \
  --manifest-path "${work_dir}/Cargo.toml" \
  --target-dir "${work_dir}/target"

expect_compile_fail() {
  local proof_id="$1"
  local capability="$2"
  local target_import="$3"
  local target_type="$4"
  local stderr_path="${work_dir}/${proof_id}-${target_type}.stderr"

  cat >"${work_dir}/src/lib.rs" <<RS
// ${proof_id}
use std::convert::TryInto;
use trnm_consensus_types::${capability};
use ${target_import};

pub fn forbidden_into(value: ${capability}) -> ${target_type} {
    value.into()
}

pub fn forbidden_try_into(value: ${capability}) -> Result<${target_type}, Box<dyn std::error::Error>> {
    let converted: ${target_type} = value.try_into()?;
    Ok(converted)
}
RS

  if cargo check --quiet \
    --manifest-path "${work_dir}/Cargo.toml" \
    --target-dir "${work_dir}/target" \
    >"${work_dir}/cargo.stdout" 2>"${stderr_path}"
  then
    echo "${proof_id}: ${capability} unexpectedly converted into ${target_type}" >&2
    exit 1
  fi

  grep -Fq "${capability}" "${stderr_path}"
  grep -Fq "${target_type}" "${stderr_path}"
  grep -Eq 'trait bound|From<|TryFrom<|Into<|TryInto<' "${stderr_path}"
  echo "compile_fail_proof id=${proof_id} capability=${capability} target=${target_type} status=pass"
}

# A22-CF-COMET-TO-GENESIS-QC
expect_compile_fail \
  A22-CF-COMET-TO-GENESIS-QC \
  VerifiedCometStateExportV1 \
  trnm_consensus_types::GenesisQcV0 \
  GenesisQcV0
expect_compile_fail \
  A22-CF-COMET-TO-CORE \
  VerifiedCometStateExportV1 \
  trnm_consensus_core::Core \
  Core

# A22-CF-PROJECTION-TO-GENESIS-QC
expect_compile_fail \
  A22-CF-PROJECTION-TO-GENESIS-QC \
  VerifiedPocoTargetProjectionV1 \
  trnm_consensus_types::GenesisQcV0 \
  GenesisQcV0
expect_compile_fail \
  A22-CF-PROJECTION-TO-CORE \
  VerifiedPocoTargetProjectionV1 \
  trnm_consensus_core::Core \
  Core

# A22-CF-CEREMONY-TO-GENESIS-QC
expect_compile_fail \
  A22-CF-CEREMONY-TO-GENESIS-QC \
  VerifiedPocoTargetGenesisCeremonyV1 \
  trnm_consensus_types::GenesisQcV0 \
  GenesisQcV0
expect_compile_fail \
  A22-CF-CEREMONY-TO-CORE \
  VerifiedPocoTargetGenesisCeremonyV1 \
  trnm_consensus_core::Core \
  Core

# A21-SEALED-NATIVE-COMMIT-VERIFIER is checked structurally by the A22 scanner:
# NativeCommitReceiptVerifierV0 must retain its private sealed supertrait.

echo "a22_inert_capability_compile_fail_summary proofs=6 status=pass"
