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
related module run. PQ signatures, signed namespaces, transaction rules and source
retirement obligations remain unchanged.

### Refuse classical owner setup before durable effects

Review of the full indicator-file set found an earlier effect boundary in two
public local constructors. `open_with_operator_task_policy` authenticated a real
Ed25519 policy, checked its settings and material catalog, opened the policy
journal and wrote the required-owner marker before the common opener refused a PQ
account configuration. `open_with_operator_mining_task_view` similarly reached
durable journal reservations and marker creation before that final refusal.

These paths did not successfully return a classical owner for PQ accounts. The
specific defect is that an ultimately refused local opening could already alter
durable state. Both constructors now reject the PQ account profile at their first
statement, with the existing `PQ_ACCOUNT_REQUIRES_PQ_NETWORK_OWNER` error, before
policy preparation, journal opening or marker creation.

Four new exact native controls use the actual public constructors, valid Ed25519
signatures and all six required material roles. Two controls use real NPQ6 account
settings and compare names, modes and bytes across the complete temporary tree,
for both an absent target and an existing empty target. Two classic-profile
controls establish that the same signed catalog can still open the corresponding
owner; the mining control also checks the two durable claims and startup CPU
accounting. These synthetic material files do not qualify model execution or Work.
The CI requires each named test and its actual execution readback. A separate
guard-removal experiment must retain its failures to establish that these controls
reach the original durable-effect defect.

## Inventory integrity is distinct from completed tracing

The historical scanner result was 1,286 Rust files, 23 role hints and 120 unreviewed
indicator files. **120 is a file count, not a vulnerability count.** The historical
`reviewed_roles_mapped` key counted a curated pathname map. The additive
`mapped_role_hints` field states its meaning, while `completed_authority_traces`
remains zero.

All 120 original indicator files received a source-context review, including
their module/build placement, authority inputs, observable effects and unresolved
obligations. This is distinct from closing 120 authority traces. The new owner
test file expands the Rust corpus and indicator set by one; its context is reviewed
separately, without turning fixture coverage into a production authority proof.
The execution record binds the baseline and updated context evidence to their own
source identities.

The revised scanner hashes every sorted Rust path and file digest, including files
with no crypto indicator. A renamed file, changed unflagged state mutation or
removed indicator changes the complete corpus identity. The selected trace checker
also binds the checked-in Cargo and toolchain input inventory, exact source anchors,
required records and explicit unresolved obligations. Stale inputs, duplicate
records, wildcard paths, missing anchors and unsupported completion claims fail.
The [trace contract](PQ_AUTHORITY_TRACE_V1.md) defines the limits of this evidence.

Both repository-truth and the PQ head/prospective-merge workflow execute the trace
checker and its negative controls. A separately registered exact native test and
actual libtest readback cover the listener guard; four additional exact tests and
readbacks cover the two owner refusals and their classic positive controls. The
original 52 required network controls and 52 release controls remain intact.
Passing source checks cannot turn any of the independent whole-chain claim gates
into qualified status.

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

The first continuation source, `28306d24b5f606fc89a6de3d7d2c08949a2b3edc`, uses
37 commands: the original 32 plus trace and native listener controls. The later
owner-effect fix requires its own 45-command run: all 37 commands, unchanged in
arguments and relative order, plus four exact owner tests and their four execution
readbacks. No result for the first source qualifies the later source. The
[execution record](../../evidence/pq-authority-effects-20261108-43ede/README.md)
reports the actual commands, source/tree, provider identity, names, counts and
failures. Historical green runs do not qualify later source, and a complete local
pass is not a hosted main-merge or production acceptance result.

Whole-authority effect coverage, historical account migration and source retirement,
independent rollback custody, capacity/invalid-input budgets, proof PQ128
qualification, quantum mining/fork choice and independent end-to-end operation
retain their existing gates. This continuation does not change activation flags,
deploy services, migrate real keys/accounts or merge the protected default branch.
