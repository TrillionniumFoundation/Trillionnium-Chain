# Retained e4abb CI failures and the original 4-second confirmation report

This is an offline readback of existing GitHub run
[`42830743518`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42830743518),
at source `e4abb172147e941b62483652b0ceabaae4317624`, tree
`016ebf3deeac88d6d7a782edf563f2291ebe17f5`. It does not execute a new native
test, supersede a failed gate, or qualify throughput. The original run remains
failed.

## First failures

| Original job | First observed failed operation | Retained result |
| --- | --- | --- |
| [repository-truth, 129995452145](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42830743518/job/129995452145) | `python3 scripts/ci/test_pq_lifetime_budget.py` | 58 test methods, one error: source-lock mismatch for `trillionnium/crates/trnm-pon-node/src/consensus.rs` |
| [protocol-contract, 129995452236](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42830743518/job/129995452236) | Original from-zero host/native runner | `CONFIRMATION_TARGET`; the service and sustained report checks passed, the confirmation report check failed |

The lifetime lock expects consensus SHA-256
`a5600aeb8287cce30ae3075b675082df4e6e5569a80f23e9a2e381f8202a8f62`;
the original e4abb source has
`dbbd44790428ae0aff32d7305e062a6fc09ca0add0e3c4c077deefd8bfec760d`.
Comparing that file with the lock's source revision
`66b7064be597039ce871b5b12ad5568850a2dd46` shows a test-module helper refactor
and the added versioned integer-vector test. The production consensus code in
that file is unchanged in this comparison. The refusal is preserved; updating
the source mapping requires a separate explicit review.

The protocol manifest records five named native invocations returning exit 0
without timeout, `all_named_tests_passed=true`, and
`terminal.native_execution_completed=true`. Its acceptance still fails. The
legacy `execution_finished=false` describes the combined execution and report
acceptance sequence; it must not be read as proof that a child process never
returned. The host controller has `systemd_run_exit=1`, `failure=null`, and
`final_host_errors=[]`. Its successful host preparation is not business
confirmation.

## Original confirmation observation

Both phases offer one signed business transaction through the same seven-packet
sequence in an original **4-second** window. They run on the same loopback host
under the controller's shared resource scope. The recorded cgroup parent uses
`cpu.max = 25000 100000`, 2 GiB memory, no swap, and a 256-process limit.

| Phase | Pressure workers | Timely submit ACKs | Timely History responses | Timely independent page replays | Independently confirmed business | Successful confirmation latency |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `attack-free-baseline` | 0 | 7/7 | 7/7 | 7/7 | 1/1 | 2,763,986,639 ns |
| `from-zero-pressure` | 16 | 7/7 | 4/4 | 3/4 | 0/1 | unavailable |

The pressure phase reports `PUBLIC_REQUEST_DEADLINE`, no independent final
confirmation, and `full_native_state_equal=false`; the receiver still reports a
valid honest prefix. These fields show that successful submission and History
responses do not imply completed independent confirmation. A missing successful
latency is not a zero-duration sample. The small finite offer does not measure
saturated TPS, WAN behavior, independent operators, or a tail-latency percentile.

This run is **distinct from the earlier `aaa3c539…` campaign set: three
campaigns, nine phases, and 30-second business windows**. Its one successful
baseline must not replace that campaign set's incomplete baseline, and the
counts and timing must not be merged.

The optional native stage snapshots remain in the raw report. Their Host,
native, packet, and replay intervals are nested and cannot be added together.
They locate observations in this run; they do not establish a unique cause for
the missed confirmation or prove that any later patch repairs it.

## Retained bytes and independent readback

`artifact-metadata.json` records GitHub artifact `13795560407`, named
`head-protocol-contract-e4abb172147e941b62483652b0ceabaae4317624-1`.
The downloaded ZIP is 6,420,228 bytes with SHA-256
`b8788fd59d9a05e9f5d22521c93f31e7f8c303e1757b06606bd74d7a152d4cd1`,
matching the artifact listing. All 93 distinct members were read with ZIP CRC
checks and independently hashed; all 50 file pins in the original native
manifest match. The archived native binary hashes to
`65244a8a9b7a74d2456a8afd8a4ac8686c7a1db7a5c7ff977c7426203dcbba85`,
matching the manifest's before/after identities. The readback did not execute it.

`raw-observations.tar.xz` retains the exact contents of 92 original members,
including the original manifest, all three reports, original test output,
SQLite files, host/controller records, and prior root-native lane observations.
The sole omitted member is the native executable; its original identity is
retained in `artifact-members.json`. Archive headers are newly generated and
are not claimed to be the original ZIP bytes. The compressed archive is
698,232 bytes with SHA-256
`1100a09cbf9fc0dcc3501cede58ba009723ad43b305816f7e2d1cd2c565a4157`.
The two `.log.gz` files preserve the connector-decoded complete job logs.

`readback.json` records the identities, file checks, terminal stages, and
results. `confirmation-observation.json` is recomputed with the existing
`run_from_zero_native.summarize_confirmation_report` reader, including its
imported source/configuration dependencies verified against e4abb. It equals
the original manifest observation exactly and retains `CONFIRMATION_TARGET`.
The existing service and sustained readers also reproduce their original
manifest results exactly. These readers check bounded report consistency;
they do not independently reverify native work, signatures, state, or host
independence.

To repeat the report readback, use an e4abb checkout or first verify the eight
reader/configuration identities in `readback.json`. Extract the retained
archive to a disposable directory, then use the existing readers:

```sh
CI_READBACK_DIR=$(mktemp -d)
tar -xJf evidence/chain-throughput-budget-20261110-065438/ci-origin/raw-observations.tar.xz -C "$CI_READBACK_DIR"
python3 - "$CI_READBACK_DIR" <<'PY'
import json
from pathlib import Path
import sys
sys.path.insert(0, 'scripts/ci')
import run_from_zero_native as reader
root = Path(sys.argv[1]) / 'from-zero-native'
manifest = json.loads((root / 'manifest.json').read_bytes())
assert reader.validate_service_report(root / 'native/report.json') == manifest['service_report']
assert reader.validate_sustained_report(root / 'native/sustained/report.json') == manifest['sustained_report']
observed = reader.summarize_confirmation_report(root / 'confirmation/report.json')
assert observed == manifest['confirmation_observation']
assert observed['original_gate_validation_error'] == 'CONFIRMATION_TARGET'
print(observed['original_gate_validation_error'])
PY
```
