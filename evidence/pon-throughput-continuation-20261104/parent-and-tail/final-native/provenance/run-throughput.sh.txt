#!/usr/bin/env bash
set -euo pipefail
export PATH=/workspace/scratch/66671f1fe103/toolchain/cargo/bin:$PATH
export CARGO_HOME=/workspace/scratch/66671f1fe103/toolchain/cargo
export RUSTUP_HOME=/workspace/scratch/66671f1fe103/toolchain/rustup
export RUSTUP_TOOLCHAIN=1.95.0-x86_64-unknown-linux-gnu
unset RUSTC RUSTDOC
export CARGO_TARGET_DIR=/workspace/scratch/7318d5f890d1/target-throughput
export CARGO_BUILD_JOBS=2
export CARGO_INCREMENTAL=0
export RUST_TEST_THREADS=1
export PYTHONDONTWRITEBYTECODE=1
export OPENSSL_DIR=/workspace/scratch/66671f1fe103/build-env/trnm-pq-provider-3.5.9.KitaGNRr/install
export OPENSSL_STATIC=1
export OPENSSL_CONF=/dev/null
export OPENSSL_MODULES=/workspace/scratch/66671f1fe103/build-env/trnm-pq-provider-3.5.9.KitaGNRr/install/lib/ossl-modules
exec "$@"
