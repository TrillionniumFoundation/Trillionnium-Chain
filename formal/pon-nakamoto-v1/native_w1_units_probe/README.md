# Native complete-W1 unit bridge probe

Status: research component, no production activation or consensus authority.

This probe uses the existing Rust `pon_work_io` and `pon_zero_io` examples. It
does not introduce another Rust work implementation, another Cargo graph or an
alternate W1 proof. Every positive unit contains the complete 49,188-byte PNW1
certificate and is checked by the existing native full W1 verifier. The retained
independently coded Python oracle must produce byte-identical complete proofs.

## Scope

The probe constructs one-unit and two-unit sets with repeated task material and
different bound challenges. It verifies each unit through the native verifier,
checks prepared/scalar producer agreement, and rejects changed challenge/index,
task, transcript, product and proof extent. A correct product with a fabricated
trace passes the cheap syntax/task/ticket filter at the inner all-ones target,
but fails actual full native verification. The zero-task control uses two legal
complete-proof algorithms and confirms that a zero-only algorithm refuses
nonzero inputs instead of silently selecting a replacement.

This is a **bridge-level** probe. Its explicitly separate probe challenge domain
is not the MU1 outer relation. The mandatory-units relation owns its complete
context, unit challenge derivation, fixed aggregate target, aggregate lottery and
credit. Those checks must be exercised separately with the same real native
bridge. The inner all-ones target removes a per-unit lottery; it does not assert
that a candidate wins the outer lottery.

No native ledger admission, task eligibility, fork selection, parameter
activation or confirmation is exercised by this script. The observed complete
work cost is not a minimum over legal classical or quantum algorithms. The
source analysis of native selection and clocks is retained separately with the
execution evidence.

## Reproduce

Use the repository-pinned Rust 1.95.0 toolchain and private Cargo home and target
directories. The commands below use the existing workspace lockfile and refuse
network dependency resolution. Set the private Cargo home to a populated,
verified offline cache before running them.

```bash
bash scripts/project-preflight.sh
cargo metadata --locked --offline --manifest-path trillionnium/Cargo.toml --format-version 1
cargo build --release --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-crypto-primitives --example pon_work_io --example pon_zero_io
cargo clippy --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-crypto-primitives --example pon_work_io --example pon_zero_io -- -D warnings
rustfmt --check --edition 2021 \
  trillionnium/crates/trnm-crypto-primitives/examples/pon_work_io.rs \
  trillionnium/crates/trnm-crypto-primitives/examples/pon_zero_io.rs
python3 formal/pon-nakamoto-v1/native_w1_units_probe/probe.py \
  --native-bin "$CARGO_TARGET_DIR/release/examples/pon_work_io" \
  --zero-bin "$CARGO_TARGET_DIR/release/examples/pon_zero_io" \
  --out /absolute/new/native-w1-bridge-probe
```

The output directory must not exist. Every actual native call retains its input,
stdout, stderr, exit status and hashes. A missing executable, native error,
unexpected acceptance, proof mismatch or receipt mismatch fails the probe; there
is no Python fallback. `calls.json` is updated after each completed subprocess so
a later failure retains earlier observations. Wall intervals include subprocess
startup and are observations, not calibrated throughput claims.

## Native binary grammar

| Binary and mode | Exact stdin bytes | Success |
| --- | --- | --- |
| `pon_work_io prove` | challenge(32), A(16,384), B(16,384) | Complete PNW1(49,188) |
| `pon_work_io verify` | challenge(32), task(32), target(32), PNW1(49,188) | Domain-bound receipt(32), exit 0 |
| `pon_zero_io generic` | challenge(32), A(16,384), B(16,384) | Prepared complete PNW1(49,188) |
| `pon_zero_io blocked-zero` | same | Complete PNW1 for supported zero material; otherwise explicit refusal |

All matrix fields are canonical little-endian u32. Task and receipt hashes use
the unchanged native domain-separated hash grammar. See the original examples
for the exact fixed-size parser and error exits.
