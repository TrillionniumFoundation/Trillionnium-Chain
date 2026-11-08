# PQ authority effects and expiry controls — 2026-11-08

Status: **HOLD** for whole-chain post-quantum qualification, main migration,
independent native acceptance and production activation.

This continuation starts from #796's delivery
`01e2c4c010c3cf65d1cf094368961efc1abab445`, whose tested source was
`ca3c4f88afc70399000b18fc7d68cfa62e57fb2f`. The
[original record](../../evidence/pq-authority-preflight-20261108-9d315/inventory-source-01/summary.json)
retains 31 passing command gates and one failed Node command. Its Node selection
executed 38 passing tests, two failing tests and one existing ignored control.
No subsequent source change changes those observations.

## Default branch and candidate have different scope

The observed protected main head is
`dd6e1c3cbeacbdc532b0679297835b3a0aac78f0`. Its
[crypto primitive](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/dd6e1c3cbeacbdc532b0679297835b3a0aac78f0/trillionnium/crates/trnm-crypto-primitives/src/lib.rs)
uses Ed25519. The independently developed PQ candidate contains actual ML-DSA
verification and selected-profile refusal boundaries. These facts do not qualify
the default chain or authorize deployment of the accumulated candidate.

[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) specifies ML-DSA signatures.
[RFC 9958](https://www.rfc-editor.org/rfc/rfc9958.html) explains the quantum threat
to traditional public-key systems and the protocol work involved in migration.
Neither standard certifies this implementation, its authority roots, its proof
backend, its current operating profile, or its state migration.

## Selected entrypoint-to-effect review

The review searched the finite checked-in Rust corpus and all 26 workspace crate
manifests. A missing source-level consumer is a scoped observation, not a proof
about external applications, generated code, macros, future dependencies or all
possible runtime configurations. The exact anchors, their byte identities and
remaining obligations are retained in the
[trace manifest](../../config/pon/pq-authority-traces-v1.json).

| Legacy surface | Actual behavior in this source | Selected PQ Node observation |
| --- | --- | --- |
| `trnm-types::TransferTx` | Verifies an Ed25519 transfer | No production consumer or Node/M06 dependency found in the reviewed corpus. Current M06 command authorization is a different path. |
| Classic settlement engine | Verifies provider/consumer signatures and changes its settlement records | Node imports the separate `native_budget` owner. No production Node call into the classic engine was found. Ordinary Node payment readback is not authenticated by those classic settlement signatures. |
| `SignedResearchCommandV1` | Verifies chain/authority/signature, then changes research maps and replay records | No other workspace crate depends on the research-protocol crate in the reviewed manifests. This remains a classic independent library requiring separate migration if deployed. |
| Hepta V1 admission | Checks the caller-provided current admission, destination, authority set and expiry | No production Node consumer was found. Verification does not automatically install a release or grant FinalUse; receiving-owner/current-history obligations remain. |
| Provider discovery V1 | Classic signatures affect its directory and explicit V1 CLI fetch destinations | The PQ CLI selects V2 records, directory, verifier and operator pins. No V2-to-V1 fallback was found. Successful fetch yields verified bytes and does not grant installation or execution permission. |

The actual M06 classic-envelope validator refuses a PQ account configuration with
`PQ_ACCOUNT_NATIVE_API_REQUIRED`. The selected Node opener requires a PQ network
owner for PQ accounts and returns `PQ_ACCOUNT_REQUIRES_PQ_NETWORK_OWNER` for an
inconsistent requested combination. The application V6 path accepts private
prepared PQ commands for its explicitly supported tags; it does not silently
route legacy secondary-signature commands into that path.

### Independent refusal at the classical listener boundary

`Node::require_classical_network_profile` now checks the retained account
configuration as well as the selected backend. This makes the final listener
refusal independent of the opener's backend/profile consistency invariant.

The new native regression deliberately corrupts only the private backend selector
under a test-only helper while retaining real PQ settings and storage. It exercises
all six existing classic listener families, retains a queued complete request to
check that no socket is accepted, compares observable current state and durable
metadata, and checks cold reopen. The public opener already refuses this
inconsistent combination. The change is defense in depth; it is not presented as
a reproduced external downgrade exploit.

The original positive classic-profile protected-head test remains required by the
related module run. The existing public constructors, PQ signatures, signed
namespaces, transaction rules and source retirement obligations remain unchanged.

## Inventory integrity is distinct from completed tracing

The historical scanner result was 1,286 Rust files, 23 role hints and 120 unreviewed
indicator files. **120 is a file count, not a vulnerability count.** The historical
`reviewed_roles_mapped` key counted a curated pathname map. The additive
`mapped_role_hints` field states its meaning, while `completed_authority_traces`
remains zero.

The revised scanner hashes every sorted Rust path and file digest, including files
with no crypto indicator. A renamed file, changed unflagged state mutation or
removed indicator changes the complete corpus identity. The selected trace checker
also binds the checked-in Cargo and toolchain input inventory, exact source anchors,
required records and explicit unresolved obligations. Stale inputs, duplicate
records, wildcard paths, missing anchors and unsupported completion claims fail.
The [trace contract](PQ_AUTHORITY_TRACE_V1.md) defines the limits of this evidence.

Both repository-truth and the PQ head/prospective-merge workflow execute the trace
checker and its negative controls. A separately registered exact native test and
actual libtest readback cover the listener guard. The original 52 required network
controls and 52 release controls remain intact. Passing source checks cannot turn
any of the independent whole-chain claim gates into qualified status.

## Two failed timing controls remain preserved

The old failure at fixture initialization occurred before the intended expiry
injection. It cannot count as successful expiry rejection. The other failure
returned `TimedOut` where the regression required `PermissionDenied`; the original
runner already used `--test-threads=1`, so fixture concurrency is not an established
cause.

The fixture now waits for its actual clock worker to enter the serving path and
records clock-exchange progress in initialization errors. For the two negative
expiry controls, setup aligns to a real integer clock boundary. The signed window
is still two trusted seconds, the clock still advances at its declared 2x BOOTTIME
rate, and the request retains its original two-second deadline. The injected pause
waits only until the same signed expiry. Assertions require reaching the injection
point before expiry and finishing the pause before the original request deadline.

The exact `PermissionDenied` message, zero admissions, unchanged durable bytes,
empty frontier and subsequent fenced refusal remain assertions. No retry,
alternate accepted error, fake clock, refreshed deadline or production timing change
is introduced. A new initialization or scheduling timeout remains a failed run;
worker readiness alone does not prove the original timeout's unique cause.

## Separate hosted provider failure

For source `01e2c4c...`, run `42468358532`, job `128693038187`, artifact
`13612169408`, the recovered original provider log records four HTTP 504 responses
while downloading the pinned OpenSSL 3.5.9 archive. Its ZIP SHA-256 matches the
GitHub artifact metadata. The receipt records exit 22 at `download`, with no source
digest verification, exported provider or native Rust PQ test execution.

The [original archive and readback](../../evidence/pq-authority-effects-20261108-43ede/prior-head-hosted-pq/readback.json)
preserve those bytes. This is distinct from the two local Node assertion failures
and from other hosted confirmation, history or work-backend failures. Other hosted
jobs are not diagnosed by this one recovered artifact.

## Fresh validation and remaining gates

Fresh validation must retain the original 32 command gates and add the trace
controls and related native listener tests on one exact committed source. The
[execution record](../../evidence/pq-authority-effects-20261108-43ede/README.md)
reports the actual commands, source/tree, provider identity, names, counts and
failures. Historical green runs do not qualify later source, and a complete local
pass is not a hosted main-merge or production acceptance result.

Whole-authority effect coverage, historical account migration and source retirement,
independent rollback custody, capacity/invalid-input budgets, proof PQ128
qualification, quantum mining/fork choice and independent end-to-end operation
retain their existing gates. This continuation does not change activation flags,
deploy services, migrate real keys/accounts or merge the protected default branch.
