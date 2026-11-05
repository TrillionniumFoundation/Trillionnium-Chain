#!/usr/bin/env bash
set -euo pipefail
export PATH=/root/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin:"$PATH"
export CARGO_HOME=/workspace/scratch/73305aff6ced/runtime/cargo
export RUSTC=/root/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/rustc
export RUSTDOC=/root/.rustup/toolchains/1.95.0-x86_64-unknown-linux-gnu/bin/rustdoc
export CARGO_TARGET_DIR=/workspace/scratch/73305aff6ced/target
export CARGO_BUILD_JOBS=1
export CARGO_INCREMENTAL=0
export RUST_TEST_THREADS=1
export PYTHONDONTWRITEBYTECODE=1
export OPENSSL_DIR=/workspace/scratch/e537ad232c79/native-runtime-acceptance/provider/trnm-pq-provider-3.5.9.P6cfOXrY/install
export OPENSSL_STATIC=1
export TRNM_PQ_OPENSSL="$OPENSSL_DIR/bin/openssl"
export TRNM_PQ_OPENSSL_SHA256=08e4988f44357113a30082b8b37b368c722dc6be82d07a8e3c3585b75e301955
export TRNM_PQ_OPENSSL_VERSION=3.5.9
export OPENSSL_CONF=/dev/null
export OPENSSL_MODULES="$OPENSSL_DIR/lib/ossl-modules"
export RUSTUP_HOME=/root/.rustup
unset RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
exec "$@"
