# Recovery, release roles and fixed-provider transport: local reproduction

Status: component observations, **HOLD** for whole-chain and deployed-effect
acceptance. No production, main-chain, FinalUse integration or independent
fault-domain qualification flag is enabled.

The candidate is composed on integration parent
`bd2777f9cc74df10ba07ae8202584ed0fb90a519`. Its concurrent model-evaluation and
legacy-reorg observation changes are preserved. Scoped component tests below were
run on their identical source bytes before this composition; no additional Node
test execution is attributed to this patch. The original cold-rollback counterexample used
`a4a0e2b561f057cfa3189979c5bf11f3a0eb2353`; the checkpoint sources are unchanged
between the original and composed parents. [observations.json](observations.json) identifies the
actual source bytes, environment, commands, results and retained log digests.
The [boundary contract](../../docs/security/PQ_RECOVERY_RELEASE_TRANSPORT_BOUNDARIES_V1.md)
describes the security claims and remaining owner obligations.

## What the actual controls establish

- A complete old checkpoint journal and its matching old sibling head were
  accepted by the former daemon's structural constructor. The retained test is a
  real failing regression, not a claim that an invalid signature became valid.
- The new daemon distinguishes first registration from recovery. Recovery
  requires the externally retained full-journal count and root before head repair
  or service binding. Missing files, extra records, same-count forks and history
  removed from another scope refuse.
- Empty-journal recovery cannot create a head that disappears after its earlier
  existence check. The actual missing-file branch receives an explicit prohibition
  on initialization. A directed stage regression preserves the failing observation
  from before this additional fix.
- Real ML-DSA-65 signatures enforce pinned root and release-role quorums, separate
  Cell activation authority, monotonic versions, root rotation, retired keys,
  ordered history recovery and the live/recovery event limit. A current root can
  approve an old bundle at a new version; an old root's signature cannot do so.
- Real loopback TLS exchanges use the pinned OpenSSL CLI and matching static
  libraries. Tests cover the three RFC 10024 hybrid groups; the narrower peer
  profile still requires its exact group and ML-DSA-65 identity. Wrong provider,
  identity, pin, protocol, group or application-purpose controls refuse.

## Observed results

| Control | Actual observation |
| --- | --- |
| Old complete-image rollback regression | 0 passed / 1 failed, exit 101; old constructor accepted the restored image |
| Empty-head deletion stage regression | Before fix: 0 passed / 1 failed; after fix: 1 passed |
| New cold-recovery integration tests | 11 passed |
| Actual CLI rejection subprocesses | 3 passed; the selector excludes three Unix-service scenarios, which are not counted as passing |
| Existing NodeCommitLedger binary tests | 15 passed |
| Release-bundle package | 16 passed, including 14 new native-signature tests |
| Fixed-provider TLS / mTLS / backend tests | 30 passed: 3 TLS, 14 mTLS, 13 backend |
| Source-integrity negative suite | 35 passed |
| Exact corpus check | 410 pinned blobs; successful integrity check still reports `HOLD_NO_GO` |
| Locked dependency graph, strict Clippy, formatting and whitespace | Passed for the recorded commands |
| Final complete checkpoint all-targets attempt | Library: 9 passed / 1 failed; Unix socket bind refused by the execution environment (`EPERM`); later test binaries did not execute in this invocation |

No test was changed to `ignore`, no environment error was converted to a pass and
no successful Unix service test is claimed. The CLI rejection tests inspect the
specific error: missing recovery expectation, checkpoint mismatch, or namespace
lock conflict. A socket permission failure cannot satisfy those assertions.

## Rust commands

Run from a complete repository checkout. These observations used Rust
`1.95.0 (59807616e 2026-04-14)`, the locked Cargo graph and an already populated
offline crate cache. Checkpoint tests used `CARGO_PROFILE_DEV_DEBUG=0`,
`CARGO_PROFILE_TEST_DEBUG=0` and `CARGO_INCREMENTAL=0`; release tests kept the
default debug profile and also disabled incremental compilation. These are local
functional controls, not optimized performance measurements.

```bash
bash scripts/project-preflight.sh

cargo +1.95.0 metadata --offline --locked \
  --manifest-path trillionnium/Cargo.toml --format-version 1

CARGO_INCREMENTAL=0 cargo +1.95.0 test --offline --locked \
  --manifest-path trillionnium/Cargo.toml -p trnm-release-bundle

CARGO_INCREMENTAL=0 cargo +1.95.0 clippy --offline --locked \
  --manifest-path trillionnium/Cargo.toml \
  -p trnm-release-bundle --all-targets -- -D warnings

export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export RUST_TEST_THREADS=1

cargo +1.95.0 test --offline --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-checkpoint-store --all-targets --all-features

cargo +1.95.0 test --offline --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-checkpoint-store --test cold_recovery -- --nocapture

cargo +1.95.0 test --offline --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-checkpoint-store --test cross_process cli_ -- --nocapture

cargo +1.95.0 test --offline --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-checkpoint-store --bin trnm-external-node-checkpoint-v2 -- --nocapture

cargo +1.95.0 clippy --offline --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-checkpoint-store --all-targets --all-features -- -D warnings

cargo +1.95.0 fmt --manifest-path trillionnium/Cargo.toml --all -- --check
```

The full checkpoint command must also run in an environment that permits Unix
domain sockets. A successful compilation or Clippy run does not replace it.

## Fixed-provider transport commands

Use the existing [provider preparation script](../../scripts/ci/prepare_pq_provider.sh)
to build a separately pinned provider and export its tested identity. It does not
replace the system OpenSSL. If a previously verified installation is reused, its
CLI, headers and static libraries must match the retained provider receipt.

```bash
trnm_provider_run=$(mktemp -d /tmp/trnm-pq-provider-reproduce.XXXXXX)
touch "$trnm_provider_run/provider.env"
RUNNER_TEMP="$trnm_provider_run" \
GITHUB_ENV="$trnm_provider_run/provider.env" \
  bash scripts/ci/prepare_pq_provider.sh
set -a
. "$trnm_provider_run/provider.env"
set +a

cd formal/pon-nakamoto-v1
python3 -m unittest -v test_pq_tls test_pq_mtls_probe test_pq_openssl_backend
```

The observed installation was OpenSSL 3.5.9. Its CLI SHA-256 was
`ec72bff5f6e4b2d9798e66b4ee338e81969ff6f8fa5a228bf312f1c57ff08818`.
The matching `libssl.a` and `libcrypto.a` hashes are recorded in
`observations.json`. The PATH-selected system executable remained OpenSSL 3.0.13.
Replaying the original TLS test sources under that environment produced two
ML-DSA setup errors even though the pinned provider had been declared. Candidate
tests use the declared provider and pass without modifying PATH to disguise that
failure. Private test keys and native binaries are temporary, not committed assets.

## Reproduce the original complete-image rollback failure

The [historical regression](baseline_cold_recovery.rs) intentionally fails on the
old structural constructor. Run it against the recorded old source, in a disposable
directory. The current daemon uses the new admitted recovery API; the legacy
structural API is deliberately still not a freshness proof and cannot serve or
export a recovery pin.

```bash
trnm_repro_root=$(pwd)
trnm_baseline=$(mktemp -d /tmp/trnm-checkpoint-before.XXXXXX)
git archive a4a0e2b561f057cfa3189979c5bf11f3a0eb2353 trillionnium |
  tar -x -C "$trnm_baseline"
cp "$trnm_repro_root/evidence/pq-recovery-release-transport-20261104/baseline_cold_recovery.rs" \
  "$trnm_baseline/trillionnium/crates/trnm-checkpoint-store/tests/cold_recovery.rs"
cargo +1.95.0 test --offline --locked \
  --manifest-path "$trnm_baseline/trillionnium/Cargo.toml" \
  -p trnm-checkpoint-store --test cold_recovery -- --nocapture
```

The expected historical result is exit 101 with
`self-consistent old journal plus anchor restored consumed history`. This result
was actually observed and retained; it is not counted as a candidate success.

The narrower empty-head deletion regression can also be reproduced in an isolated
copy of the final candidate by applying
[before_empty_head_fix.patch](before_empty_head_fix.patch) with `git apply --unidiff-zero`
and running the library
test `pinned_recovery_rejects_head_deleted_after_precheck`. That directed stage
control actually failed before the fix and passed afterwards. The patch exists
only for reproducing the historical failure; do not apply it to the integration
working tree or deploy the resulting code.

## Integrity and documentation controls

```bash
python3 -m unittest discover -s scripts/ci -p test_pq_research_integration.py -v
python3 scripts/ci/check_pq_research_integration.py
python3 scripts/refresh_distributed_source_inventory.py --check
git diff --check
```

Both dedicated authority crates now require source pins even for newly added
helpers with ordinary filenames. The source manifest also preserves and refreshes
the four pinned MVCC inputs changed by the concurrent integration parent. Updating
those byte identities does not claim additional execution of that parent's tests.
The newer parent's workflow and reorg-observation pins are preserved; the generated
distributed inventory is pinned to the combined source list.

## Remaining acceptance boundaries

Checkpoint export does not implement independent replication, authenticated
custody or an atomic external effect claim. The FinalUse/ProviderEffect owner
integration and a signed append-consistency witness remain separate obligations.
An unknown external result must retain the original operation ID; arbitrary
non-idempotent actions do not acquire an exactly-once guarantee from a local log.

The release kernel provides typed event replay, not a durable installer, complete
TUF client or TAP 21 SDK. External atomic persistence, independent fresh recovery
expectations, trusted time, actual signing-device/key-custody evidence and current
installer/activation checks are still required. Independent mldsa-native tests and
cross-architecture results are not attributed to this patch. Simultaneous rollback
of all replicas, witnesses and retained expectations remains outside the guarantee.
