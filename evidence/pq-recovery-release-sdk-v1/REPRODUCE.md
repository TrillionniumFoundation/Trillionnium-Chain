# Recovery, current publication and actual SDK continuation

Status: **component results; HOLD_NO_GO** for whole-chain or deployed-effect
qualification. Baseline: `59f75acd1d4261972b8aaa45e0c36259fcafd45c`, tree
`c0dc8282e5b2618ffb35061f108bb2fa96e9b348`.

The [compact manifest](reproduction.json) records source hashes, upstream commits,
provider hashes, actual outcomes and local observation digests. It intentionally
contains no binaries or raw-log archive. A log digest identifies a local
observation; it does not make that observation durably downloadable. Commands
below reproduce the checks, and the existing CI records fresh command outputs.
Those initial observations were local x86_64 working-tree component runs. The
later committed-source execution is recorded separately below. Neither run
qualifies ARM, a prospective merge, hosted CI or deployed-effect behavior.

## Committed-source verification

The implementation was published as
[`ac2402e4c8b99eee21c6db3e28f8984071478797`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/ac2402e4c8b99eee21c6db3e28f8984071478797),
tree `68c5fda28e64f689cabbee8cd8ae99cc7050dd74`, preserving the baseline as its
parent. It was fetched back and matched the staged tree exactly. Its author and
committer use the current account's noreply identity.

The unchanged `record_pq_native_command.py` then executed 18 scoped commands on
that clean commit. Before and after every command, the original source verifier
checked all **8,914 tracked entries / 944,799,070 bytes** against their Git blobs.
All before/after identities match. The
[committed-source record](committed-source-checks.json) preserves commands,
environment, exit status, source identity, counters and log digests.

Seventeen commands succeeded. The complete checkpoint command returned **101**
with the same **43 passed / 4 failed / 0 ignored** outcome. This is not a full
passing suite. The successful commands include the 18-test release package,
8-test original TAP21 suite, real SDK and C differential/source-attack suites,
18 original TLS/mTLS tests, scoped strict Clippy and format checks, locked Cargo
metadata, 466 source pins, 35 source-negative tests, CI contract, preflight and
the repository/link gate. The repository gate found 2,618 valid local links.
All five TLS provider inputs still match their original digests after execution.

This later record and its explanation are an evidence-only addition. They do
not rewrite the implementation commit, substitute its tested inputs, or turn
the four failed process/transport tests into acceptance. Raw logs stay outside
this compact source publication; the digests are not a raw-log archive.

## What changed

- Strict checkpoint admission now covers direct runtime APIs. A structural
  `open` cannot bypass an independently pinned recovery rejection.
- An admitted owner verifies the actual entire journal and head before runtime
  reads, pin export and CAS, and again before acknowledging durable CAS. In-place
  rollback and same-length earlier-prefix corruption are refused. Head reads
  are capped at 85 bytes. Journal validation costs O(record count) per check.
- Cell activation requires a currently published manifest with matching content,
  current root generation and unexpired publication authority. An activation
  quorum cannot renew a publisher's expired or retired authorization.
- The new SDK differential uses actual securesystemslib `CryptoSigner` and
  `SSlibKey` APIs and actual Rust TAP21 production adapters in both directions.
  The original canonical fixture and C differential controls remain present.

The [recovery/release/transport contract](../../docs/security/PQ_RECOVERY_RELEASE_TRANSPORT_BOUNDARIES_V1.md)
defines the trust and execution boundaries. The
[publication regression record](../../docs/security/PQ_CELL_ACTIVATION_CURRENT_PUBLICATION_V1.md)
explains current-root republishing and recovery compatibility.

## Actual results

| Scope | Result |
| --- | --- |
| Original checkpoint implementation plus first three new public API regressions | 11 passed, **3 failed**, exit 101 |
| Final checkpoint all-target run | **43 passed, 4 failed**, zero ignored; exit 101 |
| Final checkpoint cold-recovery binary, included above | 15/15 passed |
| Final checkpoint node-commit-ledger binary, included above | 15/15 passed |
| Final checkpoint oversized-head unit control, included above | Passed |
| Original release implementation plus two new activation regressions | 1 passed, **2 failed**, 15 filtered; exit 101 |
| Final complete release package | 18/18 passed; zero ignored; doc tests 0 |
| Actual SDK differential | 18 metadata/seed pairs; 66 SDK and 66 Rust verification decisions passed |
| SDK / original C source-attack suites | 13/13 and 9/9 passed |
| Original C/Rust differential | 20 fixed-seed signatures; 391 C and 396 Rust verification decisions passed |
| Retained Wycheproof corpus, included in C differential | All 210 matched expectations: 79 valid, 131 invalid |
| Original Rust TAP21 suite | 8/8 passed; zero ignored or filtered |
| Original fixed-provider TLS/mTLS suites | 18/18 passed; original source unchanged |
| Strict Clippy | Checkpoint/release all targets and crypto oracle example passed with `-D warnings` |
| PQ source integrity and its negative suite | 466 exact blob pins; 35/35 negative-suite tests; HOLD remains |

The checkpoint unit failure directly reports `bind checkpoint socket: EPERM`.
Three process tests report that their daemon exited at startup. The original
tests remain enabled; no socket replacement, skip or permission bypass was used.
These four results must be rerun on a host that permits the required Unix
sockets. The suite is not reported as green.

An initial SDK loader failed on the real upstream namespace package. That failed
attempt is indexed, the loader was repaired, and a regression now covers it.
One oracle build waiting on a shared target and one additional Node baseline
build were interrupted with exit 130. Neither executed tests. The latter also
reported an unqualified SQLite build boundary because `RUSTC` was not absolute.
No new Node execution or whole-runtime acceptance is attributed to this work.

## Reproduce the Rust components

Use the repository's original Rust 1.95.0 toolchain and locked graph. The local
runs used cached dependencies (`--offline`); a fresh machine must first obtain
those exact locked dependencies. Keep build outputs outside the source tree.

```bash
bash scripts/project-preflight.sh
export CARGO_BUILD_JOBS=1
export CARGO_TARGET_DIR="$(mktemp -d)"
cargo +1.95.0 test --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-checkpoint-store --all-targets --no-fail-fast -- --test-threads=1
cargo +1.95.0 test --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-release-bundle
cargo +1.95.0 test --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-crypto-primitives --test tuf_tap21
cargo +1.95.0 clippy --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-checkpoint-store -p trnm-release-bundle --all-targets -- -D warnings
cargo +1.95.0 clippy --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-crypto-primitives --example pq_message_oracle -- -D warnings
cargo +1.95.0 fmt --manifest-path trillionnium/Cargo.toml \
  -p trnm-checkpoint-store -p trnm-release-bundle -p trnm-crypto-primitives -- --check
python3 scripts/ci/check_pq_research_integration.py
python3 -m unittest discover -s scripts/ci -p test_pq_research_integration.py -v
```

To reproduce the original defects, create a separate checkout of the baseline,
copy only the corresponding final test file into it, and run the original three
checkpoint selectors or two activation selectors. Do not replace its production
implementation. The checkpoint selectors are
`structural_reopen_cannot_bypass_recovery_through_direct_owner_methods`,
`live_same_inode_rollback_cannot_export_or_extend_cached_history`, and
`live_same_length_prefix_edit_cannot_export_a_cached_journal_pin` in
`--test cold_recovery`. The release selectors are
`activation_requires_live_current_generation_manifest` and
`activation_after_root_rotation_requires_current_manifest_quorum`.
The later head-only and bounded-read controls were run on the final source;
they are not included in the recorded three-failure baseline result.

## Reproduce actual SDK and independent C interoperability

Use unmodified, separate Git checkouts of:

| Upstream | Exact commit |
| --- | --- |
| securesystemslib 1.5.1 | `15064ca640222edba024af9f13191fa5dbad3825` |
| mldsa-native v2.0.0 | `834a90d5e846ffa1e1611bd24e160bb2e9b86d35` |

Set `SDK_SOURCE` and `MLDSA_SOURCE` to those checkout directories. The source
guards reject changed or substituted tracked inputs. The SDK runner executes
captured, verified Python source and refuses an installed-package or bytecode
fallback.

```bash
export PYTHONDONTWRITEBYTECODE=1
interop_scripts=trillionnium/crates/trnm-crypto-primitives/tests/independent_backend
interop_output="$(mktemp -d)"
python3 -m venv "$interop_output/sdk-env"
sdk_python="$interop_output/sdk-env/bin/python"
"$sdk_python" -m pip install --only-binary=:all: \
  cryptography==50.0.2 cffi==2.1.1 pycparser==3.12
python3 "$interop_scripts/test_tuf_sdk_source.py" --source "$SDK_SOURCE"
python3 "$interop_scripts/test_mldsa_native_source.py" --source "$MLDSA_SOURCE"
cargo +1.95.0 build --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-crypto-primitives --example pq_message_oracle
"$sdk_python" "$interop_scripts/tuf_sdk_differential.py" \
  --source "$SDK_SOURCE" \
  --chain-oracle "$CARGO_TARGET_DIR/debug/examples/pq_message_oracle" \
  --report "$interop_output/sdk.json"
python3 "$interop_scripts/mldsa_native_differential.py" \
  --source "$MLDSA_SOURCE" \
  --chain-oracle "$CARGO_TARGET_DIR/debug/examples/pq_message_oracle" \
  --wycheproof trillionnium/crates/trnm-crypto-primitives/tests/fixtures/wycheproof/mldsa_65_verify_test.json \
  --build-dir "$interop_output/c-build" --report "$interop_output/c.json"
```

The SDK's cryptography wheel used OpenSSL 4.0.3. The separate TLS/mTLS probe used
the frozen OpenSSL 3.5.9 provider whose binary, headers and libraries are listed
in the manifest. They are separate backend observations. For TLS, provision the
original provider through the repository's existing provider workflow, set
`TRNM_PQ_OPENSSL`, `TRNM_PQ_OPENSSL_SHA256`, `TRNM_PQ_OPENSSL_VERSION` and
`OPENSSL_DIR` to that one provider, then run from `formal/pon-nakamoto-v1`:

```bash
python3 -m unittest test_pq_tls test_pq_mtls_probe -v
```

The workflow repeats the real SDK comparison on x64/ARM and candidate-head/
prospective-merge combinations and includes the full checkpoint/release command
in the existing primitive lane. New hosted results are not assumed here.

## Remaining boundaries

The direct securesystemslib signer and verifier interoperate. Its default
`Key.from_dict` mapping does not register this ML-DSA profile; this does not qualify
a complete TUF updater. Publication-role enforcement is an owner component,
not a deployed installer or running-Cell revocation service.

Independent fresh checkpoint retention, a deployed effect-consumption witness,
actual FinalUse/budget/effect atomic composition, provider reconciliation and
power-loss/fault-domain testing remain required. Restoring every replica,
witness and backup together leaves no independent fresh fact. C2SP consistency
and cosignature interoperability, production key/device custody, whole-chain
PoN security and original-budget capacity qualification remain separate gates.
