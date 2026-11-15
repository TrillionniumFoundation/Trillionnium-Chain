# PN1 and PN4 source audit, 2026-11-01

Source checked: `TrillionniumFoundation/Trillionnium-Chain` at
`cea95fb44d8152a0eb1138727619fcced056f496` (PR 559, still draft and open).
PR 674 was independently read at `605af09da34ca72665f822200a2f3e75573e6052`;
its test-only diagnostic change is a separate source and is not imported here.

## Demonstrated PN1 defect

`trillionnium/crates/trnm-crypto-primitives/src/pon_work/rejection_cache.rs`
originally computes its cache key by hashing the entire supplied proof before
checking its length. The underlying `checked_proof_inputs` rejects any width
other than `PROOF_BYTES = 49,188` before reading proof bytes. Consequently, the
optional public Rust cache wrapper turns the native constant-cost wrong-width
rejection into work proportional to an arbitrarily large caller slice. This is
a library API resource-bound defect. The restored call graph confirms that
`PublicServer::with_w1_rejection_cache` is opt-in and defaults to off. Ordinary
`Packet::decode` in `trnm-pon-node/src/lib.rs` requires the remaining proof width
to be exactly 49,188 bytes; the PQ decoder in `pq_application_v6.rs` enforces the
same width. This audit therefore does not establish a reachable oversized-proof
network exploit through those decoders.

The proposed narrow correction admits cache keys only for the exact proof
width and delegates all other inputs to the original verifier. It preserves
the original `Length` error priority, including when version/task/target are
also invalid, and preserves the absence of cancellation callbacks for these
cheap rejects. It changes no valid proof, consensus domain, target, task,
budget, cache lifetime or cache capacity.

The existing cache context includes profile, challenge, task, target and all
proof bytes. Only `Transcript` and `Product` failures are cached. Hits still
execute the cancellation checkpoint; cache poisoning disables reuse. No hit
creates `VerifiedWork` or grants authority. The sibling positive fact caches
already invoke `checked_proof_inputs` before reading their key fields.

## PN1 conclusions that remain unqualified

The exact work relation and full-verifier correctness are different from a
minimum producer-cost guarantee. Fresh false trace claims can pass the cheap
ticket check after only hash trials and still require a full receiver replay.
The existing `four_distinct_from_zero_false_traces_each_owe_first_full_replay`
control explicitly preserves that failure case. Exact negative cache hits do
not cover rotating traces, tasks, challenges or attacker identities.

The frozen security statement permits legal preprocessing, structured/zero
tasks, amortization, optimized hardware and failed attempts. Existing paired
cost documentation reports that its new integer-paired zero producer is slower
than the earlier blocked-zero producer on the retained campaigns; fewer
counted multiplications are not a measured work-security advantage. No new
hardware, energy or quantum experiment was executed in this audit.

## PN4 reviewed invariants and remaining boundary

Reviewed source:

- `trillionnium/crates/trnm-service-settlement/src/native_budget.rs`
- `trillionnium/crates/trnm-service-settlement/src/engine.rs`
- `trillionnium/crates/trnm-service-settlement/src/store.rs`
- `trillionnium/crates/trnm-service-settlement/src/types.rs`
- `trillionnium/crates/trnm-pon-node/src/store/funding/payment.rs`

The native adapter observes actual owner state instead of accepting a supplied
funding amount. Funding source ceilings and unpaid commitments are checked
across budgets; indivisible native sources retain whole-amount semantics.
An append is read back in the transaction and again after commit before a new
intent is returned. A retry after an uncertain commit returns pending or done,
not new dispatch authority. Operation identities are globally reserved within
the durable journal; an unknown physical outcome consumes the entire original
resource reservation. Branch reorganization does not erase that journal.

Historical payments are reobserved against the same owner and exact original
beneficiary, source, subject, operation and amounts. Readback failure does not
authorize another payment. Node payment observation reexecutes the selected
native transition; a matching SQL row or balance difference alone is not
payment proof. These are code-reviewed mechanisms, not a new execution result.

No additional reproducible PN4 defect was established in this bounded review.
The local journal is not target-side exactly-once execution, independently
funded storage, a banking receipt, future repair capacity or contribution
benefit. Actual funds, target reconciliation and service execution remain
separate required evidence. A model/API implementation of the trusted owner
trait cannot substitute for the Node owner in a completion claim.

## Evidence boundary

The patch was applied to the parent agent's exact restored source after
`scripts/project-preflight.sh` passed. Rustfmt passed. The original locked,
offline crypto-package test was actually attempted and failed because the
precise `ml-dsa` package is absent from the registry cache. Existing cache
inspection found 39 missing exact versions across the complete workspace lock.
No lock versions or dependency constraints were changed.

A separate source-module harness copies all 17 native W1 module files with
SHA-256 and Git-blob identities. It retains all original module tests, the one
new width test, the exact original SHA-256 dependency graph, and the original
optimized module test profile with debug and overflow checks. All 96 native W1
tests passed, including the new malformed-width case, with zero failures and
zero ignored tests. The unchanged original negative-cache test still proves
that each distinct forged trace requires its first full replay. Source hashes
matched before/after execution; all 11 registry package identities matched the
original workspace lock and neither lockfile changed. Compile plus execution
took 28.57 seconds; the test runner reported 0.18 seconds. The test ELF SHA-256
is `e922d7dee5a719e8cd517cc13a42447faecdf9b20aa2aeb7921ef79ea151e74b`.

This is explicitly not the full crypto/PQ package or workspace build; its
result and the failed full-package attempt are recorded separately under
`pn1-validation`.

## Narrow native cost counterexample and corrected comparison

The original and patched complete W1 modules were compiled into separate fresh
targets with the same Rust 1.95.0 compiler, default release profile, empty
Rustflags, identical Cargo config/profile fingerprints and identical 11-package
lock identities. Each of four predetermined malformed widths was invoked 256
times through the public negative-cache API. Inputs and returns used
`std::hint::black_box`; every call returned `Length` and none reached a progress
callback. Input allocation and cache setup were measured separately outside
the call interval. Clock overhead remains in the call measurements.

| Wrong proof width | Original total process CPU ns | Patched total process CPU ns |
| --- | ---: | ---: |
| 3 bytes | 119,477 | 4,627 |
| 49,187 bytes | 7,430,460 | 3,756 |
| 1 MiB | 161,599,659 | 3,865 |
| 16 MiB | 2,519,313,497 | 7,681 |

These are all observed calls, with no timing acceptance threshold, confidence
bound or hardware-general performance claim. Wall time, allocations, setup,
binary hashes and complete build logs are retained in `length-cost-report.json`
and its sibling raw records. Baseline ELF SHA-256:
`4137b14657e7016e5b547f0782436ad4eac9ca69285824d3322b6a410fa57978`.
Patched ELF SHA-256:
`157477825943c484e44fa240f1d449b76b632bf7d837ea63fe64889c67f204c5`.

The first attempt incorrectly reused one target directory for the two copied
packages. Cargo treated the second build as fresh, and its identical ELF hash
revealed that both measured the original implementation. That attempt is
explicitly invalidated and retained under
`invalid-shared-target-cost-attempt`; no patched-effect inference uses it.

The exact W1 source harness also passed Clippy with `-D warnings`. All 172
source files of the ten actually available/compiled registry packages were
compared byte-for-byte against their Cargo-lock-checksummed `.crate` archives.
The eleventh locked package, libc, is a cpufeatures dependency for other
architectures and was not needed on this x86_64 Linux execution.

No remote write, production activation, hardware qualification, independent
administrator claim or WAN completion is made by this audit.
