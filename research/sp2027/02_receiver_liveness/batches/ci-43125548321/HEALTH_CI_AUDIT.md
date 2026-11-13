# Original healthy-control batch: CI 43125548321

## Observed decision

**Three of three no-pressure controls independently confirmed before the
original four-second cutoff.** The native decision is
`HEALTH_GATE_PASSED_CONTROLS_PENDING`. This independently identified batch
contains no pressure-stratum execution and establishes no attack mechanism.
Its native `first_divergence` is null. The collector's successful exit is not
used as a substitute for these raw business gates.

Original sources: [run 43125548321](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43125548321),
[job 130876572920](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43125548321/job/130876572920),
[artifact 13902664465](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43125548321/artifacts/13902664465).
The [machine-readable audit](HEALTH_CI_AUDIT.json) has SHA-256
`08911937e8cfc18e5bb4b441d7ac1a95edabddcb4e56f627cbcf27e3b048f9cd`.

| Denominator or outcome | Actual count |
| --- | ---: |
| Planned controls | 3 |
| Attempted controls | 3 |
| Completed controls | 3 |
| Incomplete controls | 0 |
| Unstarted controls | 0 |
| Independently confirmed operations | 3 |
| Pressure controls executed | 0 |

Every completed arm has `workers=0`, T=`4,000,000,000 ns`, the original native
final gate true, one credited business, a true invariant result, equal native
state, an empty verification-error list, and zero observer loss or measurement
failure. Each has seven honest submission calls, seven History calls, and seven
independent replay attempts. No failed/late honest submission or History call
appears in the inspected business call arrays. Full raw member identities are
in [RAW_SHA256.json](RAW_SHA256.json).

| Control | Business start, ns | Confirmation end, ns | Remaining window, ns | Native final gate |
| --- | ---: | ---: | ---: | --- |
| 0 | 152,537 | 3,182,777,296 | 817,222,704 | true |
| 1 | 95,730 | 3,093,116,433 | 906,883,567 | true |
| 2 | 102,201 | 3,099,623,590 | 900,376,410 | true |

The times above are relative to each phase's own original epoch. They are not
cross-phase absolute timestamps. Three healthy observations qualify this
finite control batch; they do not establish a population success rate or
capacity guarantee. The earlier fixed-order 1/1 versus 0/1 pair remains a
different batch and retains its original failed result.

## Immutable source and executable identity

The actual tested source is commit
`0bc51795a978494af1b4659712ecf78c290c1a88`, tree
`adb6ee5208cc2e8d9f8afd374ccb9a336c3a1d1c`. Preparation and execution
before/after source records agree. The independent audit reads that exact Git
object, verifies the tree, and checks every recorded source-file digest against
its actual Git bytes. The native process records matching compiled test/module
digests and run identity; it is not merely a runner-declared source string.
See [HEALTH_CI_AUDIT.json](HEALTH_CI_AUDIT.json).

| Item | Verified identity |
| --- | --- |
| Original ZIP | 5,389,637 bytes; SHA-256 `db8960d8388dadb29450e525de1e3eaa71a2ae87d5d897c0e1ce9afb711bf312` |
| Native executable | `sp27-receiver-controls/public_v3_from_zero`; 12,125,656 bytes; SHA-256 `81c19f2dbfc709b87160cda7cdbb995842d83c445f0097dd6f485fd125cfd67f` |
| Compiled test source | SHA-256 `b86f7b73f06720727fa63caaf1bac679c8bb4b2747e45ec90d2413e22288e328` |
| Compiled health module | SHA-256 `37ccfdeb41ba15b4c911f1d843bf456938474d98691956433a4deb01359d7fe4` |
| Original execution collector | SHA-256 `6d064bfcfae745adbb5cc4acd6ddc3290a7b515960c58ec7ef9d5ea54c841d74` |

The archive passes its CRC checks. All 64 retained files are independently
hashed, including the actual executable and original native raw records.
Preparation binary identity, execution before/after identity, and native
self-read binary identity all match those executable bytes. The source's
non-pressure safety, publication, and activation boundaries remain unchanged.
See [artifact metadata](artifact-metadata.json), [job readback](jobs.json),
and the [complete member index](RAW_SHA256.json).

The raw phase files are:

| Member beneath `sp27-receiver-controls/native/` | SHA-256 |
| --- | --- |
| `raw/health-000.json` | `c1427ce79cbdcdca101ca44e61751be01dcd8a926fd5024c63bde99ef307fcde` |
| `raw/health-001.json` | `ecd11e5ca3f7b59158861db9b17063ec0b1dd5e207da8c524bf920634e771977` |
| `raw/health-002.json` | `bb5b62420659c4140c1dc37f3189956ed432027cb11700fa2504dcabc6f2db9e` |

## Actual Host and resource boundary

The native hostname is `runnervm7aw5e`, boot ID
`f0aabebf-265d-4b1b-8e0f-a5c5a242e809`. The original fixed parent is
`/sys/fs/cgroup/trnmponpublic.slice`, device/inode `31/7343`, root-owned 0755,
without a symlink. Its service is
`trnm-from-zero-43125548321-1-health-5375.service`. Runner before/after Host
snapshots and native before/after Host checks agree; error fields are empty.

| Resource/permission field | Before and after |
| --- | --- |
| `cpu.max` | `25000 100000` (0.25 CPU) |
| `cpu.max.burst` | `0` |
| `memory.max` | `2147483648` (2 GiB) |
| `memory.swap.max` | `0` |
| `pids.max` | `256` |
| UID/GID | `1001/1001` |
| `NoNewPrivs` | `1` |
| `CapBnd` | `0000000000000000` |

The original parent was fresh (`parent_reused=false`), and the same cooperative
parent lease is recorded before and after. This verifies fixture ownership and
the bounded aggregate parent. It does not establish exclusive physical CPU or
remove the shared-parent relationship among receiver, clients and independent
verifier. Runner cpuset and process snapshots are retained in the original ZIP;
their presence does not turn a quota into exclusive physical allocation. These
limits are expressly preserved in [HEALTH_CI_AUDIT.json](HEALTH_CI_AUDIT.json).

## Acquisition, execution cost, and the 90-second boundary

The original `native/acquisition.json` records seven-block acquisition wall time
`190,514,822 ns` and process CPU `41,769,970 ns`. Its declared scope includes all
process threads during mining and acquisition, excludes earlier producer
opening/setup and later service, and is not pure W1 cost or exclusive actor CPU.

The named native child actually ran for `12,587,443,240 ns` wall time and
`2,474,753,000 ns` process CPU, exited zero, and did not time out. The original
collector passes 90 seconds to `run_child` around this executable. That limit
does not include all earlier/later Python identity checks and Host-wrapper work.
The runner's inside-before to inside-after snapshot interval is
`52,781,619,000 ns`, a different scope. These observations must not be added as
independent costs or described as the same outer-timer measurement. The exact
[collector source](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/0bc51795a978494af1b4659712ecf78c290c1a88/scripts/ci/run_sp27_receiver_controls.py)
and [native process receipt](HEALTH_CI_AUDIT.json) define the scopes.

Empty-block packets are 49,508 bytes, including a 49,188-byte PNW1 proof; their
canonical Submit JSON is 99,043 bytes. The first business packet contains one
199-byte transaction and totals 49,709 bytes, with 99,445-byte Submit JSON. The
audit parses the original u16 count/length wire layout and checks every proof
length. **Sixteen distinct valid siblings were not generated or timed in this
batch.** Any extrapolation for future control scheduling remains an estimate.

## Independent strict-consumer readback

SP27-06's new strict reader separately consumed the original preparation object,
three raw records, acquisition, source/binary identities and Host before/after
records. It produced [HEALTH_V2_CONSUMER_RECEIPT.json](HEALTH_V2_CONSUMER_RECEIPT.json),
SHA-256 `a49907f53da6d7e12070df330dc8f989006299fd54460799f55f088d335ac7ac`.
That is a later analysis readback, not a claim that the original CI executed the
later reader. The original collector manifest and raw records were preserved.
Neither provenance audit nor strict readback executes native traffic.

## Sibling QROM failures, without changing their gates

The [QROM implementation run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43125562453)
and [QROM closure run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43125561958)
fail in both head and prospective-merge jobs. Their first concrete diagnostics
are retained in [SIBLING_QROM_CI_AUDIT.json](SIBLING_QROM_CI_AUDIT.json), including
four complete decoded-log hashes, tracebacks and seven file comparisons.

The implementation audit rejects
`formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs`: actual length is 11,172 bytes,
but the pinned contract allows 9,233 bytes. The closure roster fails in
`setUpClass`, before any lifetime-ledger tests run, because `consensus.rs` has
SHA-256 `dbbd44790428ae0aff32d7305e062a6fc09ca0add0e3c4c077deefd8bfec760d`, while
the selected source pin expects
`a5600aeb8287cce30ae3075b675082df4e6e5569a80f23e9a2e381f8202a8f62`.

Both target files, both audit scripts, both relevant test scripts, and the
implementation contract are byte-identical between common base
`5b591754b426c6f88bea6d399fafcd77e31255d8` and tested head `0bc51795…`. Therefore
these specific first-failure predicates already exist in the common-base bytes.
This is a source comparison; no base CI was rerun, and it does not attribute
every possible failure in those workflows. Their gates were not relaxed, pins
were not changed, and no unrelated QROM repair was attempted.

## Reproduction and preserved archive

The locally retained original archive is
`/workspace/scratch/e8159a5f91bf/provenance/ci-43125548321/artifact-13902664465.verified.zip`.
The original bytes and extracted files are locally read-only. Hashes and eventual
versioned publication bind their identities; file permission bits alone are not
an immutable-storage guarantee. The original GitHub artifact expires according
to [its metadata](artifact-metadata.json), so the exact ZIP should accompany the
durable delivery package.

Run the independent provenance audit from the Chain root with a new output
directory:

```sh
bash scripts/project-preflight.sh
python3 -B research/sp2027/02_receiver_liveness/audit_health_ci.py \
  /absolute/path/artifact-13902664465.verified.zip \
  --source-repo . \
  --out /absolute/path/health-provenance-readback
```

The source-audit script SHA-256 is
`a0efd596c1f5483520b1093e252997c90e69428963992221ff24edf57f6bc42e`.
It performs no new native run and does not overwrite existing receipts.
