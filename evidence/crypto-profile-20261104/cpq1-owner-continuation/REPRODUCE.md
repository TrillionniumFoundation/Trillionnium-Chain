# Complete CPQ1 parameter and original owner continuation

Scope: **candidate observations and component verification only; whole-chain PQ remains HOLD**.
This increment continues PR #698 from
`b525fbc6dc780343c78710c98a94616f7cff59e4`. It preserves the original
TRNMCPB1 observer, complete CPQ1/legacy signature rules, every native acceptance
selector, compiler profiles and resource ceilings. No runtime profile is activated.

## What the new executable measures

`pq_profile_bench` calls the actual candidate protocol and cryptographic APIs.
Its 32 cases cover ML-DSA-65/87, 1/2/4/8 signers and payload lengths
0/176/4096/the maximum legal value for each signer count. Eleven stages retain
complete signing/self-verification/encoding, encoding using existing signatures,
cold and warm authentication, distinct syntax/context/cryptographic refusals,
and a shared-budget mixed valid/invalid batch. The encode stages explicitly call
`candidate_message`; `candidate_wire` also reconstructs that message as part of
its real contract. The reported combined cost includes both calls and the
assertions and owned temporary drops. Every measured sample verifies
its exact outcome and reservation counters. A missing completion sentinel is
an incomplete run.

The shared-budget stage has exactly one budget within each sample: one valid
request, wrong-purpose requests through 64 reserved verifications, one charged
over-budget request and one latched refusal whose counters cannot change.
Different timing samples have separate budgets by design. Reserved attempts
are not reported as cryptographic arithmetic calls.

The independent Python reader checks the actual public fixture framing,
profile identities, coverage, accounting and every raw timing statistic. Its
synthetic mutation controls establish reader behavior only. Actual native
execution, provider interoperability, authority and production capacity have
their own acceptance obligations.

## Reproduce on the exact checked-out source

Choose an isolated development checkout and keep outputs outside it. Run the
existing preflight and recorder, without modifying either:

```bash
set -euo pipefail
bash scripts/project-preflight.sh
source_sha="$(git rev-parse HEAD)"
pq_output="$(mktemp -d)"
export CARGO_TARGET_DIR="$pq_output/target"
export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS=1
export RUST_TEST_THREADS=1
export PYTHONDONTWRITEBYTECODE=1

record() {
  label="$1"
  shift
  python3 scripts/ci/record_pq_native_command.py \
    --kind head --candidate "$source_sha" --tested "$source_sha" \
    --label "$label" --output "$pq_output/records" -- "$@"
}

record compiler rustc +1.95.0 -Vv
record locked-graph cargo +1.95.0 metadata --locked \
  --manifest-path trillionnium/Cargo.toml --format-version 1
record reader-negatives python3 -m unittest discover -s scripts/ci \
  -p test_cpq1_parameter_observation.py -v
record cpq1-build cargo +1.95.0 build --release --locked \
  --manifest-path trillionnium/Cargo.toml -p trnm-crypto-primitives \
  --example pq_profile_bench
sha256sum "$CARGO_TARGET_DIR/release/examples/pq_profile_bench" > "$pq_output/binary.sha256"
record cpq1 "$CARGO_TARGET_DIR/release/examples/pq_profile_bench" --samples 64
record cpq1-readback python3 scripts/ci/check_cpq1_parameter_observation.py \
  "$pq_output/records/cpq1.log"
```

Record CPU, memory, kernel and load around the command as well. These are local
wall times including scheduling, fixture checks and temporary-object drops.
At 64 samples the nearest-rank p99 equals the observed maximum. No stable
parameter speed ratio, population tail or network result follows from one run.

## Original runtime controls

The original full-feature command is:

```bash
cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --lib --all-features --no-run --message-format=json
```

Prepare or independently verify the pinned OpenSSL 3.5.9 provider using the
existing [`prepare_pq_provider.sh`](../../../../scripts/ci/prepare_pq_provider.sh)
contract. Keep the exported provider binary/header/library identities in the
command record. A reused provider must be described as reused, not newly built.

After a successful build, retain the original 49 selectors in
[`pq-system-required-tests-v1.json`](../../../../config/pon/pq-system-required-tests-v1.json)
in their original order. Execute each using the same Cargo target, features,
`--exact --show-output --test-threads=1`, original recorder and
[`check_required_native_test.py`](../../../../scripts/ci/check_required_native_test.py).
A successful zero-test filter does not satisfy any selector.

The full `ingress::pq_network` family contains 34 tests, and
`operator_pq_auth::tests` plus `operator_pq_startup::tests` contain 18. With the
original roster, their union is 94 unique tests on the pinned parent. Keep
child-process harnesses excluded from the original meaningful-control count.
The complete retained Node library suite and all-target workspace Clippy remain
separate commands; a subset pass cannot be substituted for either.

## Attribution and remaining blockers

Actual command receipts and compact results are added only after execution.
The implementation commit, later evidence-only commit and parent observations
must remain distinct. Preserve unsuccessful, interrupted and unknown commands;
later successes do not overwrite their files or reclassify them.

The registry's current/retired policy still requires a real owner to authenticate
and persist its state. Static NPQ/PNQ mappings do not supply dynamic activation
or retirement. Operator's different full-message grammar remains explicitly
unregistered. Cross-owner CURRENT/FinalUse, whole-effect monotonic recovery,
historical migration, original-hardware/WAN capacity and independent W1
proof/mining security remain unqualified. All six PQ domain gates and production
activation remain false.
