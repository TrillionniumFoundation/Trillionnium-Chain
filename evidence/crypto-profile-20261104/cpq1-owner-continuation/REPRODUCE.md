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

## Independently verify every actual fixture signature

After preparing or verifying the pinned OpenSSL provider, use the separate
[`verify_openssl_fixtures.py`](verify_openssl_fixtures.py) helper. This parser does
not import the observation reader. It checks the frozen 32-case CPQ1 grammar,
full signed messages and profile-bound public-key identities, then asks the
actual OpenSSL default provider to verify every signature with Pure mode,
`message-encoding:1`, `mu:0` and empty context. Each signature also has three
mathematical rejection controls: wrong message, a flipped signature `c_tilde`
bit and a different FIPS context. Fresh OpenSSL keys establish actual SPKI OIDs
and positive nonempty-context controls before any fixture result is counted.
CLI, initialization and parsing failures are not accepted as signature refusals.

```bash
: "${TRNM_PQ_OPENSSL:?verified OpenSSL 3.5.9 executable is required}"
: "${TRNM_PQ_OPENSSL_SHA256:?verified provider binary digest is required}"
record cpq1-independent-openssl python3 \
  evidence/crypto-profile-20261104/cpq1-owner-continuation/verify_openssl_fixtures.py \
  --input "$pq_output/records/cpq1.log" \
  --openssl "$TRNM_PQ_OPENSSL" \
  --output-dir "$pq_output/openssl-fixtures" \
  --expected-input-sha256 "$(sha256sum "$pq_output/records/cpq1.log" | cut -d ' ' -f 1)" \
  --expected-openssl-sha256 "$TRNM_PQ_OPENSSL_SHA256" \
  --source-sha "$source_sha"
```

The output directory must not already exist. The helper preserves command-level
outputs and an unsuccessful summary on errors. Its source association is
caller-supplied; the surrounding original recorder supplies checkout identity
and terminal status. This is **Rust-to-OpenSSL mathematical interoperability**;
reverse interoperability, owner authorization and FIPS module certification are
not established by it. The new four-cell CPQ1 CI matrix runs the observation and
independent reader; this additional OpenSSL experiment is a separate local
reproduction command, not an unobserved CI pass.

## Original runtime controls

The original full-feature command is:

```bash
cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --lib --all-features --no-run --message-format=json
```

Prepare or independently verify the pinned OpenSSL 3.5.9 provider using the
existing [`prepare_pq_provider.sh`](../../../scripts/ci/prepare_pq_provider.sh)
contract. Keep the exported provider binary/header/library identities in the
command record. A reused provider must be described as reused, not newly built.

After a successful build, retain the original 49 selectors in
[`pq-system-required-tests-v1.json`](../../../config/pon/pq-system-required-tests-v1.json)
in their original order. Execute each using the same Cargo target, features,
`--exact --show-output --test-threads=1`, original recorder and
[`check_required_native_test.py`](../../../scripts/ci/check_required_native_test.py).
A successful zero-test filter does not satisfy any selector.

The full `ingress::pq_network` family contains 34 tests, and
`operator_pq_auth::tests` plus `operator_pq_startup::tests` contain 18. With the
original roster, their union is 94 unique tests on the pinned parent. Keep
child-process harnesses excluded from the original meaningful-control count.
The complete retained Node library suite and all-target workspace Clippy remain
separate commands; a subset pass cannot be substituted for either.

## Attribution and remaining blockers

The compact [actual result index](RESULTS.json) binds implementation commit
`13986046c9c0e0e3d0d1c76b399bea11878e0ab6`, tree
`e25d21e5dbfd308abb0095d1a5845e583e399b0d`, binaries and original command logs.
A later publication commit adds this index, the byte-identical independently
hashed OpenSSL helper, CI host metadata and documentation corrections. It is not
retroactively substituted for the source of the recorded native measurements.
The OpenSSL helper was external to that implementation checkout; its own SHA-256
is recorded separately. Parent observations, unsuccessful commands and the
initial interrupted receipt remain distinct.

Actual observations on the frozen implementation source:

| Check | Observed result |
|---|---|
| Complete CPQ1 benchmark | 32 cases, 352 measured groups, 22,528 raw values, completion sentinel and terminal exit 0 |
| Independent framing/statistics reader | Exit 0; all raw samples, identities, lengths and counters recomputed |
| Crypto primitives / protocol | 143 / 102 tests passed; protocol retains its original 2 ignored tests |
| Compile-fail documentation contracts | 4 passed |
| Strict Clippy | Entire workspace, all targets, all features, `-D warnings`: exit 0 |
| Python controls | 238 tests across 8 suites passed; zero skipped |
| Rust-to-OpenSSL full fixture signatures | 120 accepted; 120 wrong-message, 120 signature-bitflip and 120 nonempty-context refusals; 2 positive context controls and 2 changed-context refusals |
| Original all-feature Node build on parent `b525fbc6` | Cargo exit 101; compiler terminated by signal 9/SIGKILL after about 986.5 seconds; shared cgroup OOM-kill counter rose during the run |
| Original 49 / expanded 94 owner controls | Not executed: the original Node build did not produce a test executable |
| Repository checker on implementation source | Exit 2 for incorrect relative links; original failure retained, three links corrected by publication |

The original compiler profiles, 49 selectors, verifier, recorder, provider
contract and resource ceilings were not relaxed. A shared-host failure does
not establish a source regression or a successful runtime control. The Node
library suite and owner tests still need a successful original build on a host
with sufficient available resources. No repeated memory-constrained build is
reported as a test pass.

### Complete frame sizes and local observations

| Signers | Payload | Signed message | ML-DSA-65 wire | ML-DSA-87 wire |
|---:|---:|---:|---:|---:|
| 1 | 4,096 B | 4,367 B | 9,644 B | 11,602 B |
| 1 | 65,265 B (maximum) | 65,536 B | 70,813 B | 72,771 B |
| 8 | 4,096 B | 4,815 B | 46,975 B | 62,639 B |
| 8 | 64,817 B (maximum) | 65,536 B | 107,696 B | 123,360 B |

These are complete **candidate CPQ1** wires, including keys, signatures and
metadata. They do not redefine live transaction limits. Both candidate profiles
remain refused by the current-authorization selector. The maximum-message case
fits the existing candidate 131,072-byte wire cap without raising it.

The run reserved 200,192 verification attempts and returned 23,040 verified
signatures in successful complete observations; those are different counters.
There were 81,920 verification API calls and 6,144 complete accepted observations.
All counts exclude setup and warmup. Partial internal successes before a late
signature rejection are not promoted to a complete successful observation.

For an eight-signer, maximum-message frame, measured hot-verification p50 was
3.303 ms for 65 and 3.513 ms for 87. This was one shared x86_64 host with an
8 GiB cgroup limit and eight-CPU quota. Load averages around the run exceeded the
quota. Each reported p99 at 64 samples equals that group's observed maximum;
timing reversals and scheduling outliers must not be interpreted as a stable
parameter speed ranking, production p99, original-hardware or WAN qualification.
The result index retains additional selected raw-nanosecond summaries and all
32 frame sizes. The full public fixtures and raw timing rows remain execution
artifacts rather than a large Git evidence dump.

The cached OpenSSL 3.5.9 provider was verified and reused, not rebuilt in this
turn. Its binary SHA-256 is
`35f28c82e7e4fdcd06b0a42062efd224a5fd5d32d5cc9894252f8206219d496e`.
The initial external-helper probe rejected the provider's ordinary mathematical
failure diagnostic on stderr; that unsuccessful probe is preserved. After
checking the precise OpenSSL diagnostic path, the corrected helper completed
all 494 OpenSSL commands, and a separate root execution repeated it under the
original exact-source recorder. Neither observation overwrites the failed probe.

The registry's current/retired policy still requires a real owner to authenticate
and persist its state. Static NPQ/PNQ mappings do not supply dynamic activation
or retirement. Operator's different full-message grammar remains explicitly
unregistered. Cross-owner CURRENT/FinalUse, whole-effect monotonic recovery,
historical migration, original-hardware/WAN capacity and independent W1
proof/mining security remain unqualified. All six PQ domain gates and production
activation remain false.
