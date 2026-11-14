#!/usr/bin/env bash
set -euo pipefail
export PATH=/root/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin:"$PATH"
export CARGO_HOME=/workspace/scratch/7318d5f890d1/runtime93/cargo
export RUSTC=/root/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/rustc
export RUSTDOC=/root/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/rustdoc
export CARGO_TARGET_DIR=/workspace/scratch/e537ad232c79/target
export CARGO_BUILD_JOBS=1
export CARGO_INCREMENTAL=0
export RUST_TEST_THREADS=1
export PYTHONDONTWRITEBYTECODE=1
export OPENSSL_DIR=/workspace/scratch/7318d5f890d1/runtime93/provider/trnm-pq-provider-3.5.9.FzmBhGf2/install
export OPENSSL_STATIC=1
export TRNM_PQ_OPENSSL="$OPENSSL_DIR/bin/openssl"
export TRNM_PQ_OPENSSL_SHA256=ec72bff5f6e4b2d9798e66b4ee338e81969ff6f8fa5a228bf312f1c57ff08818
export TRNM_PQ_OPENSSL_VERSION=3.5.9
export OPENSSL_CONF=/dev/null
export OPENSSL_MODULES="$OPENSSL_DIR/lib/ossl-modules"
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
exec "$@"
