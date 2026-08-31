#!/usr/bin/env bash
set -euo pipefail

root=$(git rev-parse --show-toplevel)
source_dir="$root/trillionnium/crates/trnm-poco-lab-validator"
manifest="$root/trillionnium/Cargo.toml"
lockfile="$root/trillionnium/Cargo.lock"

for path in \
  "$source_dir/src/candidate_devnet.rs" \
  "$source_dir/src/bin/trnm-poco-candidate-devnet-validator.rs" \
  "$source_dir/tests/candidate_devnet_cli.rs" \
  "$manifest" \
  "$lockfile"; do
  test -f "$path"
done

tmp_base=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
work=$(mktemp -d "$tmp_base/trnm-candidate-devnet-clippy.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/src" "$work/tests"

cp -- "$source_dir/src/candidate_devnet.rs" "$work/src/candidate_devnet.rs"
cp -- "$source_dir/src/bin/trnm-poco-candidate-devnet-validator.rs" "$work/src/main.rs"
cp -- "$source_dir/tests/candidate_devnet_cli.rs" "$work/tests/candidate_devnet_cli.rs"

python3 - "$work/Cargo.toml" "$source_dir" <<'PY'
from pathlib import Path
import json
import sys

manifest = Path(sys.argv[1])
source_dir = sys.argv[2]
quoted_source = json.dumps(source_dir)
manifest.write_text(
    f"""[package]
name = "trnm-candidate-devnet-clippy-harness"
version = "0.0.0"
edition = "2021"
publish = false

[lib]
path = "src/lib.rs"

[[bin]]
name = "trnm-poco-candidate-devnet-validator"
path = "src/main.rs"

[dependencies]
anyhow = "=1.0.103"
serde_json = "=1.0.149"
trnm-poco-lab-validator = {{ path = {quoted_source} }}
""",
    encoding="utf-8",
)
PY

cat > "$work/src/lib.rs" <<'EOF_LIB'
#![forbid(unsafe_code)]

mod config {
    use std::path::Path;

    #[derive(Debug)]
    pub struct LoadedValidatorConfig;

    impl LoadedValidatorConfig {
        pub fn load(_root: &Path, _config: &Path, _binary: &Path) -> anyhow::Result<Self> {
            Ok(Self)
        }

        pub const fn has_local_consensus_secret(&self) -> bool {
            true
        }

        pub const fn has_local_p2p_identity_secret(&self) -> bool {
            true
        }

        pub const fn has_local_operator_recovery_secret(&self) -> bool {
            true
        }

        pub fn commission_deployed_ordinary_runtime_v1(&mut self) -> anyhow::Result<()> {
            Ok(())
        }
    }
}

mod consensus_report {
    pub const MAX_CONSENSUS_RUN_BLOCKS_V1: u64 = 1_000_000;
    pub const MAX_CONSENSUS_RUN_DURATION_SECONDS_V1: u64 = 86_400;
}

mod p2p_admission {
    use std::{path::Path, time::Duration};

    pub trait ExternalPeerLeaseAuthorityV1 {
        type Error: std::fmt::Display;

        fn preflight(&self) -> Result<(), Self::Error>;
    }

    #[derive(Debug)]
    pub struct UnixExternalPeerLeaseAuthorityV1;

    impl UnixExternalPeerLeaseAuthorityV1 {
        pub fn connect(_path: &Path) -> Self {
            Self
        }

        pub const fn with_timeout(self, _timeout: Duration) -> Self {
            self
        }
    }

    impl ExternalPeerLeaseAuthorityV1 for UnixExternalPeerLeaseAuthorityV1 {
        type Error = anyhow::Error;

        fn preflight(&self) -> Result<(), Self::Error> {
            Ok(())
        }
    }
}

mod consensus_runtime {
    use std::{path::PathBuf, sync::Arc, time::Duration};

    use crate::{
        config::LoadedValidatorConfig,
        p2p_admission::UnixExternalPeerLeaseAuthorityV1,
    };

    pub const MINIMUM_CONSENSUS_RUN_BLOCKS_V1: u64 = 3;

    #[derive(Debug)]
    pub enum BoundedConsensusRunOutcomeV1 {
        CompletedReport(PathBuf),
        Process1TargetParked(String),
    }

    pub fn run_bounded_consensus_with_external_fence_v1<F, T>(
        mut config: LoadedValidatorConfig,
        _duration: Duration,
        _max_blocks: u64,
        _report: PathBuf,
        _fence: Arc<UnixExternalPeerLeaseAuthorityV1>,
        commission: F,
    ) -> anyhow::Result<BoundedConsensusRunOutcomeV1>
    where
        F: FnOnce(&mut LoadedValidatorConfig, ()) -> anyhow::Result<T>,
    {
        let _ = commission(&mut config, ())?;
        if std::hint::black_box(false) {
            Ok(BoundedConsensusRunOutcomeV1::Process1TargetParked(
                String::new(),
            ))
        } else {
            Ok(BoundedConsensusRunOutcomeV1::CompletedReport(PathBuf::new()))
        }
    }
}

#[path = "candidate_devnet.rs"]
pub mod candidate_devnet;
EOF_LIB

sha256sum \
  "$source_dir/src/candidate_devnet.rs" \
  "$work/src/candidate_devnet.rs" \
  "$source_dir/src/bin/trnm-poco-candidate-devnet-validator.rs" \
  "$work/src/main.rs" \
  "$source_dir/tests/candidate_devnet_cli.rs" \
  "$work/tests/candidate_devnet_cli.rs"
cmp -- "$source_dir/src/candidate_devnet.rs" "$work/src/candidate_devnet.rs"
cmp -- "$source_dir/src/bin/trnm-poco-candidate-devnet-validator.rs" "$work/src/main.rs"
cmp -- "$source_dir/tests/candidate_devnet_cli.rs" "$work/tests/candidate_devnet_cli.rs"

export CARGO_TARGET_DIR="$work/target"
cargo clippy \
  --manifest-path "$work/Cargo.toml" \
  --all-targets \
  --no-deps \
  --offline \
  -- \
  -D warnings

git -C "$root" diff --exit-code -- "$lockfile"
test -z "$(git -C "$root" status --porcelain --untracked-files=all)"
printf 'candidate_devnet_clippy=passed source_bytes=exact dependency_lints=excluded\n'
