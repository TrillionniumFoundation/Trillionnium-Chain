# Evaluation integrity and weight loading — 2026-11-04

## Source and scope

This increment extends Chain PR #688 from
`93e207c8d2ccb8509f78566223abc371b9d8118b`. Before publication, concurrent Cell
residency commit `5c070abeb61d0ea8702fa94fffe9330d1699119c` and its generated
inventory correction `a4a0e2b561f057cfa3189979c5bf11f3a0eb2353` were retained in
the ancestry. Only the canonical plan overlapped; both continuation sections
are preserved. The enclosing Git commit identifies the patched source. The Cargo
lockfile is unchanged, SHA-256
`773cd1364a02cc70b017412350e2343172ae4f2a8770b044a5a307e33a638d0a`.
Observed tools: Rust 1.95.0 and Python 3.12.14, using the retained locked Cargo
graph and default test profile. No dependency or protocol namespace was changed.

The [canonical plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [six acceptance obligations](../../docs/protocol/pon-nakamoto-v1/MODEL_COMMONS.md#preventing-optimization-of-the-evaluation-process)
retain the unclosed production requirements. This change does not activate a
model, install an artifact, qualify a new Chain/Hepta pair or award a reward.

The read-only Hepta inspection is pinned to
`e0b4c82e129d42d98cb9a98bf97fe41d1e3b1b53` (PR #4696). Its existing V8 execution
profile pins Chain `73ab6e9a83bcc836e261d93f9bb23ceafe556758`. Those 42 source
pins were not rewritten. Old execution evidence does not qualify these new
runtime bytes.

## Repairs

Retained native evaluation records now recompute every reveal's original
commitment at classic/PQ hydration, closure and adoption/component consumption.
The check also validates roster membership, the commit/reveal relation and the
existing score/evidence bounds. Existing signed domains, stored formats, closure
vectors and legal zero-score component behavior remain unchanged. A valid chunk
digest does not prove that its decoded reveal matched its original commitment.
The tests inject malformed stored state; they do not demonstrate remote bypass
of an authenticated chain state root.

The existing runtime child now binds role, frozen recipe, artifact kind, source
and immutable predecessor. Its artifact record must contain exactly the existing
12 fields. The same bounded regular-file byte snapshot supplies file hashes,
tensor parsing and material identity. Exact names, F32 dtype, shape, offsets,
complete byte coverage and finite values are checked before parameter copies.
All target profiles are checked before the first copy; existing loaded-root
readback remains. A weight record confers no code execution authority.

## Observed tests

These rows overlap; their counts must not be summed as unique tests.

| Observation | Result and boundary |
|---|---|
| `trnm-mvcc-fee --all-targets`, default features | 212 executed PASS, 7 existing opt-in timing tests ignored, 0 failed, exit 0; 25 binaries have complete terminal results. The default-feature `pq_account_owner` binary contains zero tests. |
| The same package, `--all-targets --all-features`, supported OpenSSL 3.5.9 | 220 executed PASS, 7 existing ignored, 0 failed, exit 0. Includes all 8 real PQ account-owner tests and the original Rust/Python wire/signature/fee interoperability check; counts overlap the default run. |
| Retained reveal regression within that suite | 3 legal scenarios × 4 mutated fields × adoption/hydration/reclosure = 36 rejection assertions; legal closure vectors still pass. |
| Existing PQ release/mature-claim test within that suite | Real ML-DSA harness; component/bundle × 4 fields × hydrate/read/original tag8 = 24 rejection assertions, with original valid release, claim and economic-owner assertions retained. |
| `test_llm_runtime_artifact_loading.py -v` | 17 methods PASS. Real child control flow, parser, file/hash/material checks and refusal receipts; tiny Tensor/model/forward doubles, not real Torch or LLM inference. |
| `test_llm_parent_material.py -v` | 11 methods PASS. |
| `test_llm_runtime_pilot.py` | 294 registered: 183 executed PASS, 111 existing opt-in/environment SKIP, exit 0. Includes the new loader tests. |
| Existing evaluation/bundle/acceptance and native oracle tests | 77 methods PASS. |
| Existing pending/aborted/history/exposure window tests | 55 methods PASS. |

The runtime environment used for these Python checks does not have Torch or
Safetensors installed. No 135M model, GPU, behavioral backdoor battery,
independent evaluator or prospective held-out cohort was executed. The finite
byte checks above cannot establish behavioral safety or useful net improvement.

## Old-source failures retained

Production files were archived from the exact base commit and only the new test
files were overlaid. The old Python child ran six selected methods, with 13
negative subcase failures because the expected `ValueError` was not raised;
the unchanged immutable positive control passed. The refused-after-patch cases
include an unknown kind that skipped loading, candidate/backbone impersonation,
incorrect immutable roots and extra or false artifact authority fields.

An independent loader review also exercised these attacks against old and new
child paths, with the same explicitly marked NumPy Tensor/model doubles:

| Input | Old source | Patched source |
|---|---|---|
| F64 singleton broadcast into an F32 matrix | Accepted; two parameter copies | `PARENT_MATERIAL_TENSOR_PROFILE`; zero copies |
| Hash file A, reopen substituted B, claim B's material root | Accepted B | `RUNTIME_FULL_TUNE_RELOAD`; zero copies |
| Last full-tune tensor contains NaN with a matching material root | Accepted; two copies | `RUNTIME_ARTIFACT_NONFINITE`; zero copies |
| Valid complete F32 material | Accepted | Accepted with exact bytes |
| Replace the path after reading the checked byte snapshot | Previously used a second open | Loads only the original checked snapshot |

The old classic/quorum source fails the new exact regression with exit 101:

```text
"legacy-all-reveal": commitment cannot be adopted
left: Ok(())
right: Err("PUBLIC_EVAL_COMMITMENT_BINDING")
test result: FAILED. 0 passed; 1 failed; 0 ignored; 2 filtered out
```

The old PQ production source also fails its original test with the added
malformed-state assertions, exit 101 after a successful compile and real ML-DSA
execution:

```text
component commitment hydrate
left: None
right: Some("PUBLIC_EVAL_COMMITMENT_BINDING")
test result: FAILED. 0 passed; 1 failed; 0 ignored; 119 filtered out
```

The first attempt to run old native source in a shared Cargo target reused a
new-source library and reported a pass. That observation is invalid as an
old-source test. After cleaning the affected package and forcing recompilation
from the archived production path, the failure above was observed. Use separate
target directories when reproducing across source roots. An initial independent
Python invocation from the repository root used an unsupported module import
path and failed before tests ran; direct script execution then passed all 17.
An initial old-source PQ build omitted the repository's `tests/` vector inputs
and failed at `include_str!`; that was a preparation error, not a rejected
attack. The reproduction archive below includes those exact base vectors.

Strict all-feature Clippy first stopped because `pkg-config` was absent. Explicit
paths to the system's OpenSSL 3.0.13 SDK then exposed the expected missing
`PKey::private_key_from_seed` API in the retained PQ test. Neither attempt is a
pass. Using the already installed OpenSSL 3.5.9 SDK with its actual include/lib
paths and `OPENSSL_STATIC=1` passed `--all-targets --all-features -- -D warnings`;
no dependency was changed or check disabled. This compiler observation alone
does not establish provider runtime or model execution qualification.

## Reproduce the patched checks

Run from this checkout with its pinned Rust toolchain and installed Python test
dependencies. Offline Cargo execution requires the locked dependencies to be
available in the local cache.

```bash
bash scripts/project-preflight.sh
cargo metadata --manifest-path trillionnium/Cargo.toml --locked --offline --format-version 1 > /tmp/chain-evaluation-cargo-metadata.json
cargo fmt --manifest-path trillionnium/Cargo.toml --all --check
cargo test --manifest-path trillionnium/Cargo.toml --locked --offline -p trnm-mvcc-fee --all-targets
cargo clippy --manifest-path trillionnium/Cargo.toml --locked --offline -p trnm-mvcc-fee --all-targets --all-features -- -D warnings
python3 scripts/test_llm_runtime_artifact_loading.py -v
python3 scripts/test_llm_parent_material.py -v
python3 scripts/test_llm_runtime_pilot.py
python3 scripts/ci/check_repository.py
python3 scripts/ci/test_repository.py
python3 scripts/ci/test_ci_source_integrity.py
bash scripts/ci/check_canonical_development_plan.sh
```

The all-feature Clippy command requires the supported OpenSSL 3.5+ development
SDK. When `pkg-config` is unavailable, explicitly set `OPENSSL_INCLUDE_DIR` and
`OPENSSL_LIB_DIR` to that SDK, with `OPENSSL_STATIC=1` for the retained static
installation. Optional provider runtime tests additionally require the existing
`TRNM_PQ_OPENSSL`, SHA-256/version and matching `OPENSSL_DIR` oracle pins; the
default-feature test run alone does not certify that provider. The observed
provider-enabled run used OpenSSL 3.5.9 and executable SHA-256
`ec72bff5f6e4b2d9798e66b4ee338e81969ff6f8fa5a228bf312f1c57ff08818`.
These are local component observations, not public-network or model qualification.

## Reproduce native failures against the old production source

Archive only source and overlay the two changed Rust tests. Use a fresh target
directory so an earlier patched build cannot masquerade as an old-source run.
Both commands below are expected to return 101 from the actual failed assertion,
not a compile error or zero matched tests.

```bash
chain_old=$(mktemp -d)
git archive 93e207c8d2ccb8509f78566223abc371b9d8118b trillionnium config formal tests rust-toolchain.toml scripts | tar -xf - -C "$chain_old"
cp trillionnium/crates/trnm-mvcc-fee/tests/evaluation_quorum_v2.rs "$chain_old/trillionnium/crates/trnm-mvcc-fee/tests/evaluation_quorum_v2.rs"
cp trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/application_v6_tests.rs "$chain_old/trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/application_v6_tests.rs"
CARGO_TARGET_DIR="$chain_old/target" cargo test --manifest-path "$chain_old/trillionnium/Cargo.toml" --locked --offline -p trnm-mvcc-fee --test evaluation_quorum_v2 retained_reveals_recheck_commitments_at_restore_close_and_adoption -- --exact --nocapture
CARGO_TARGET_DIR="$chain_old/target" cargo test --manifest-path "$chain_old/trillionnium/Cargo.toml" --locked --offline -p trnm-mvcc-fee --lib pon_executor::pq_accounts_v2::application_v6_tests::actual_pq_evaluation_release_and_mature_claim_use_original_economic_owner -- --exact --nocapture
```

All six production obligations remain tied to real owners and fresh evidence.
In particular, failed/missing-cost execution is not a successful no-update,
self-generated role keys are not independent administration, and one binary
correctness channel is not complete-composition resource/net-utility evidence.
