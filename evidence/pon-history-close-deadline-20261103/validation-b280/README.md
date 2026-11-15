# Concurrent CAS and Host fixture composition: native validation

This is a fresh source-bound follow-up to the [3898/8a74 execution record](../validation/README.md).
It validates published `b28098c092dca72165c0d26054fce95a8636d777`, tree `7c39ccecd82f05a3d68857efdef9e8c67bdf8069`,
which preserves the concurrent [runtime-fixture continuation](../../pon-runtime-fixture-closure-20261103/README.md).
The earlier sources' passes are not inherited as a result for this source.
**All-blocker closure, public readiness and activation remain false.**

## Completed on this exact source

| Check | Actual result |
| --- | --- |
| Fresh native library test build | PASS, unmodified repository release profile |
| History deadline and retained native controls | 7 passed |
| Retained client/store CAS controls | 3 passed |
| New committed-CAS deadline controls | 4 passed |
| Total selected native controls | **14 passed; 0 failed; 0 ignored** |
| Local Host adapter/controller controls | **78 unique controls passed** |
| Source-pin and negative source-integrity controls | **34 + 34 passed** |
| Strict Clippy | PASS, `--workspace --all-targets --all-features -- -D warnings` |
| Original formatter | PASS |
| Main/fuzz locked Linux graphs | 26/138 and 1/106 workspace/resolved packages |
| Source pins and embedded inventory | 376 blobs and 1,158 paths verified |
| Repository contract | 1,852 local links; 26 workspace packages; 24 normal dependency edges |
| Full source and executable identities | Clean and unchanged before/after |

Executable SHA-256: `9e51ef0a2fd597fd2e21d73f739b2e7da362ecdd9dd33099c699b18ff4bf450e`.
Cargo's actual artifact record binds its profile and input identity. The release
profile has optimization 3, no debug information, debug assertions off and
overflow checks off. No profile override was introduced. This is functional
evidence and does not satisfy the original test-profile build or CPU gates.

The 78-control controller invocation also imports the 17 architecture, 17 lease
and seven process controls. Their earlier separate executions are retained but
are not counted as another 41 unique controls. Real pidfds, flock conflicts and
owned process-group cleanup were exercised; root/systemd/Host provisioning in
these local controls was mocked. The actual fixed-Host positive fixtures still
require the original hosted run. No local marker is accepted as Host authority.

## What the four new native controls establish

The successful CAS path retains a completed authenticated receipt after the real
witness COMMIT crosses the original deadline. The store validates and aligns
that exact committed fact before reporting expired live authority. The controls
retain pre-COMMIT rollback, late Current refusal, the original socket write
deadline and the paid local/durable state. They use temporary state, normal
CAS/Current operations, a 200 ms deadline and one Unix socketpair. They do not
establish WAN behavior, independent witness ownership or production acceptance.

The original local-versus-real-owner CAS refusal controls remain intact. History
still checks late success only after its required cleanup, with original errors
and committed facts preserved. The History coverage limits in the prior record
remain; no cleanup-only expiry injection was added by this validation.

## Remaining gates and audit trail

Original test-profile builds, full workspace and ARM CPU acceptance, real Host
positive fixtures, original public confirmation windows/campaigns and work-cost
qualification remain open. Independent operators/evaluators, prospective model
benefit, sustained custody, economic obligations, durable external effects,
quantum/DAA and whole-chain PQ/release evidence remain separate. The claim guard
still reports all six PQ gates **UNQUALIFIED**. No service budget or qualification
flag changed during these runs.

[Status](status.json), [original execution receipts](execution-records.json),
[complete raw output](raw-logs.json.gz) and the [file manifest](manifest.json)
preserve all commands, source identities, compiler artifacts, test names and
digests. The logs are gzip-compressed JSON, with no compiled executable included.
Earlier formatter/build/offline-cache failures, the unknown original-profile
build and historical confirmation failure remain in the prior evidence record.
