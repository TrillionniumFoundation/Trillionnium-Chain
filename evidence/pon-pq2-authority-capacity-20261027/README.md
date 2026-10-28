# Actual PQ2 authority-command capacity controls

This continuation adds two real M06 integration cases to the native PQ2 source
at `3be3d15d6bfb721f3c96848c235f17051eafbd51`. It does not change account rules,
signature domains, fees, work, target, DAA, migration trust or activation.

The prior nine-case Node target checks the 122 maximum-memo-transfer boundary.
It does not execute the distinct double-proof rotation and migration-claim
boundaries. The new [integration target](../../trillionnium/crates/trnm-mvcc-fee/tests/pq2_authority_capacity.rs)
uses genuine ML-DSA-65 signatures and the actual public M06 execution entry.

| Actual command cohort | Bytes | Result |
| --- | ---: | --- |
| 56 dual-key rotations | 519,232 | Executed; 112 signature verifications, actual authority updates |
| 57 dual-key rotations | 528,504 | `PQ2_TRANSACTION_LIMIT`; input State unchanged |
| 55 anchored migration claims | 518,760 | Executed; 110 signature verifications, imported nonce 7 advances to 8 |
| 56 anchored migration claims | 528,192 | `PQ2_TRANSACTION_LIMIT`; input State unchanged |

The original aggregate transaction budget is 524,288 bytes. The tests include
every witness, public key and signature byte. The migration control retains a
56th imported account as locked/unclaimed, checks each claimed marker and nonce,
and checks that `meta:issued` changes only by the original 1,000-unit block
subsidy. Actual execution also checks the original monetary conservation/root
rules; claims do not issue the imported balance a second time.

The source checkpoint in this M06 control is explicitly a synthetic trusted
fixture, as in the existing M06 migration controls. Its independently selected
prior-PQ registry, source-chain finality and retirement are not proved here.
This is separate from the real source-Node checkpoint/cold/reorg control already
implemented in `native_pq_v2`.

## Execution and retained failures

The isolated probe was compiled with the actual Rust 1.95.0 compiler and linked
read-only against the already compiled native PQ2 M06, protocol and ML-DSA
libraries. Exact arguments, direct library hashes, compiler version, input
source, final binary hash and raw outputs are retained. The final formatted
source executed **2 passed / 0 failed / 0 ignored / 0 filtered**, in **18.15s**
test wall time. The wrapper observed 18.17s including launch/collection. This
shared-host time is not an isolated CPU cost, throughput or worst-case bound.

The first compile failed because the test called two crate-private helpers; its
original source and diagnostics remain in `capacity-01`. The correction uses
the public controlled-execution entry and an infallible test progress callback.
The earlier unformatted probe passed in 19.41s and remains `capacity-02`; the
first formatted source passed in 28.15s and remains `capacity-03-final`.
Warnings-denied Clippy then rejected two `.err().expect()` test expressions.
Using `expect_err` preserves the same negative requirement; the final
`capacity-04-linted` source passes both Clippy and the two actual tests. These
earlier observations are not relabeled as final-source success.

The initial sparse-checkout Python checks lacked the existing
`formal/pon-nakamoto-v1/bounded_process.py`; the original import failures remain
in `sparse-attempt-01`. After including that tracked dependency, the exact
runner tests passed **13/13** and source-integrity negatives passed **34/34**.
The first inventory check correctly refused the unlisted new Rust target; the
inventory was then regenerated and checked successfully. No gate was removed.

The dedicated PQ2 runner now requires both exact capacity test names, with zero
ignored or filtered cases. Its parser rejects a one-case result, an ignored
boundary, a filtered result, or the unrelated nine Node cases as substitutes.
Run it under Cargo with:

```sh
cargo test --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-mvcc-fee --test pq2_authority_capacity -- --test-threads=1 --show-output
```

## Reproduced native capacity failure and completed nine-case rerun

The prior `attempt-09-native-frozen` has no terminal receipt in the observed
workspace. Its partial stdout is retained as `prior-native-terminal-unknown`;
four `ok` lines and an unfinished capacity line are not a completed command.
All 1,164 source inputs matched the original before-source map when read back.

A separate selected-case run of its actual retained ELF reproduced the capacity
failure: the second 16-member group returned 32 `typed_gate_admissions`, while
the test expected 16. The original `PoolReceipt` contract and implementation
count the complete reconstructed pending prefix. The fix retains the full
122/123 byte-limit, original PoN verification, SQL activation and nonce controls;
it requires the exact cumulative count from **both** admission and ready-metadata
counters after every group. No pool or execution rule was weakened.

The corrected **entire nine-case native target** was compiled against the
unchanged original libraries and executed with zero filtering: **9 passed /
0 failed / 0 ignored / 0 filtered in 64.03s**. The strict reader accepted all
nine exact names and **196 actual phase observations**, including eight groups
totaling 122 full-size transactions. All 102 linked Rust libraries and the
patched test source retained identical before/after hashes.

The cases execute the actual ML-DSA, M05 pool, M06, full W1, SQL, cold-open and
heavier-fork paths; dual-key rotation retains task ownership; a non-genesis miner
earns six ordinary rewards, waits the original 20-block maturity and pays the
5,891-unit byte-inclusive registration fee without a registry whitelist. The
actual source-Node migration case exports an admitted W1 checkpoint, claims its
locked balance and task permissions, reopens cold, and detaches/reattaches on a
heavier fork. Its independent prior-PQ registry and source-chain finality/retirement
remain external premises. The new capacity test adds the separate synthetic
M06 boundary controls described above.

`native-remainder-01` retains the original ELF's four selected-case passes and
the actual 122-capacity failure; the filtered passes are never described as a
full suite. `native-patched-01` retains the full successful target, 102-library
hash map, binary hash, exact source and strict readback. The two changed Rust
integration targets pass direct warnings-denied Clippy. This is **not** a new
full Cargo workspace/Clippy or physical-I/O qualification. The compiled native
binaries are locally retained and SHA-bound, but are not embedded here.

The original raw files and source snapshots are hash-indexed by `manifest.json`.
Production activation and whole-chain PQ qualification remain
false. The existing limitations on other command/inner-signature owners,
independent migration trust, source-chain retirement, physical I/O, custody,
transport and Hepta Final-use remain.
