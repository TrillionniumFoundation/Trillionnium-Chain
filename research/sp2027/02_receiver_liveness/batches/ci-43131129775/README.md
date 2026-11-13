# Additional healthy-control batch: CI 43131129775

This directory preserves a separate original CI batch. It does not replace the
earlier healthy batch at commit `0bc51795a978494af1b4659712ecf78c290c1a88`, the
fixed-order baseline/pressure pair, or any failed run. It contains no new native
execution performed by the audits.

## Exact identities

| Item | Observed identity |
|---|---|
| Source commit | `ff35430d27eea56dd803e05aa6d48573e37ed4c9` |
| Source tree | `ccf72585d2ac3b361ec169a62a607d7bce055582` |
| Run / attempt | `43131129775` / `1` |
| Job | `130895251212` |
| Artifact | `13907325153` |
| Original ZIP bytes | `5536414` |
| Original ZIP SHA-256 | `a426ab09abffc6aa128dd5875be6ec33d72da55ca538bdd9867d0b56feaee073` |
| Retained executable bytes | `12504464` |
| Retained executable SHA-256 | `52093ac76963ae8bb2a2e9b17bfb23fe82e706bf6b45f5aacc788a751a66bcd5` |
| Native host / boot ID | `runnervm7aw5e` / `8cb17039-0a2b-4ed9-a660-1fd1411fbc5b` |

The original [run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43131129775)
and [job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43131129775/job/130895251212)
are read back in `run.json`, `jobs.json`, and the decoded job log.
`artifact-metadata.json` retains the platform-provided byte count and digest.

## Observed outcome and boundaries

The native report contains 3 planned, 3 attempted, 3 completed healthy controls,
3 independent business confirmations, 0 incomplete and 0 unstarted controls.
Pressure controls executed: 0. First divergence: `null`. Its qualification is
`HEALTH_GATE_PASSED_CONTROLS_PENDING`; mechanism status remains `UNKNOWN`.

| Health index | Confirmation endpoint, ns | Original window, ns | Original final gate |
|---|---:|---:|---|
| 0 | 1800867959 | 4000000000 | true |
| 1 | 1792501261 | 4000000000 | true |
| 2 | 1801097967 | 4000000000 | true |

Each raw record has zero workers, one independently confirmed transaction,
native-state equality, no verification error, and no observer loss/failure.
The endpoints satisfy strict `< T`; the preserved native final gate is also
required. `HEALTH_V2_CONSUMER_RECEIPT.json` records a second, actual invocation of
the frozen reader on the original preparation and run files.

Host before and after observations retain `cpu.max=25000 100000`,
`cpu.max.burst=0`, `memory.max=2147483648`, `memory.swap.max=0`, `pids.max=256`,
UID/GID 1001, `NoNewPrivs=1`, and zero bounding capabilities. Host read-error
collections are empty. The fresh fixture's cooperative parent lease and parent
identity agree before and after. These establish fixture eligibility and
cooperative ownership; exclusive physical-CPU use is not established.

The native child took 12624870152 ns wall and 1586552000 ns CPU with no timeout.
The 90-second cap applies to that native child. The distinct Host snapshot
interval is 47394743000 ns. Neither scope is a per-transaction cost estimate.
Different source/binary/host identities prevent attributing the shorter
confirmation endpoints relative to the earlier batch to a source change.

## Exact-byte reconstruction and audit

`ARTIFACT_PARTS.json` names two consecutive slices of the original downloaded
ZIP. No member was reserialized or repackaged. From the Chain repository root:

```bash
BATCH=research/sp2027/02_receiver_liveness/batches/ci-43131129775
python3 "$BATCH/reconstruct_archive.py" --out /absolute/new/artifact-13907325153.zip
GIT_NO_LAZY_FETCH=1 python3 "$BATCH/audit_original.py" \
  /absolute/new/artifact-13907325153.zip \
  --source-repo . --out /absolute/new/health-audit
python3 "$BATCH/intake_original_zip.py" \
  --archive /absolute/new/artifact-13907325153.zip \
  --metadata "$BATCH/artifact-metadata.json" \
  --artifact-id 13907325153 --run-id 43131129775 \
  --head ff35430d27eea56dd803e05aa6d48573e37ed4c9 \
  --out /absolute/new/verified-originals
```

Output paths must be new. Reconstruction was actually performed and its full
ZIP SHA-256 matched the platform digest. `audit_original.py` is the exact source
used to generate `HEALTH_CI_AUDIT.json`: SHA-256
`5cb3ff608e5cfd8df0cf08c1e31575cc2ce7ec1a2798cbeb01881d83123f2405`.
The earlier audit source is retained unchanged. This pinned audit checks this
observed healthy batch; it does not manufacture reports for missing or failed
batches. The intake script preserves every regular original member and does not
classify scientific success.

All 64 regular ZIP members were consumed with CRC verification and SHA-256
recording. `RAW_SHA256.json` is the audit member inventory;
`ZIP_MEMBER_SHA256.json` additionally retains ZIP CRC values.
`BATCH_MANIFEST.json` hashes the delivered files except its own bytes.
