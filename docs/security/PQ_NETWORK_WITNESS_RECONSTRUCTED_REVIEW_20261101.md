# Reconstructed PNQ2 admission and witness: internal source review

Date: 2026-11-01.

This is an internal implementation review and a reconstruction record. It is
not an independent cryptographic audit, a public-network qualification, or a
whole-chain post-quantum certificate.

## Source and evidence boundaries

The reconstruction starts at Chain commit
[5606a97104f9cd3243befc2921ccace3fae2c369](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/5606a97104f9cd3243befc2921ccace3fae2c369).
The earlier scratch source and patches were lost. The reconstruction does not
have byte-for-byte identity evidence against those lost files. In particular,
the old review digest and historical native test counts do not qualify this
candidate. This document has its own identity.

The following file digests identify the reviewed handoff, before any later
integration edit:

| File or patch | SHA-256 |
| --- | --- |
| Admission patch, production plus five tests | 9d41bd7c3945cf5bfe3b44a3d881d1a3ae61f9eaac3000e6cec4c21eb36a115b |
| Five-test-only patch | 8f80bec57f10343f0a7b8c7bf5c8e2b0252647edacf19e1166e2aedd6402831b |
| Ingress witness-deadline increment | 8aae313ccb0f3eec630e1a9b8e71f8eb008895bf4742ffb1d1cfe2f9361e260e |
| Ingress source after both increments | 95192458ef2cc7b282001b5f38f6510791e54114c0af7a1da7add2a77d4fa9d8 |
| ingress/pq_network/live_admission_tests.rs | 0673850f4918e42fcfbb784e9500e0302ed7266fab8d6badc473352bcefd845b |
| pq_rollback_witness.rs | 3ba705c5d7a205f6d2568168ce9fe232c46a799ff9eee8812f5b2bcea38071b8 |
| pq_rollback_witness/tests.rs | aba46d037d24fef98ab4f91fd3c743f0e99f7c14501f862ebb20326ada82f83f |
| store/pq_rollback_witness.rs | e79383690c7c9fd6aa0d95f81277fc414eff831c268887a03d1f21adca19eae5 |
| store/pq_network.rs | 3e5d090177bf88520928bac2dc034b78a9b86c816f09e56cf30348cae65a2be6 |
| store/pq_rollback_witness/tests.rs | a26a24da5d6a2bd6221206f9fbad294c4b1b46b9806d8d7940f8b832eecb2e1a |

The source file paths in this table are relative to
trillionnium/crates/trnm-pon-node/src/.

## Fresh baseline counterexample

The five network tests were added to the unchanged production baseline, in
commit e34f2d2f63ea0d10232b3440e93ce20e508e8a73, tree
64e27258405f82aa41b80d040a581626c19b0f6b. The recorded command used Rust 1.95.0,
the original locked/offline Cargo graph, all features, the library test target,
and one test thread. The recovered-network-red.json record reports matching
verified source before and after the command and exit code 101.

The test result was one pass and four behavioral failures. This fresh run had
working loopback sockets; its intake failure was not the earlier sandbox
permission error. The passing control submitted a real PQ transfer after a bad
signature on the same sequence and verified the persisted balance increase of
42. The four failures covered an elapsed entry deadline, a deadline while
waiting for the owner, signed expiry while waiting for the owner, and cancelled
socket intake before connection credit could be consumed.

The raw log digest in the command record is
96241cdbf5807442db2bc863656b6ef4facf90bcde54fee15aa7bfc1ba346fa5.
This record is baseline RED evidence; it does not prove the reconstructed
production source passes. The integrating owner must attach fresh GREEN
records to the exact final candidate.

## Findings and implemented corrections

| Finding | Correction or source-review result |
| --- | --- |
| Blocking owner acquisition ignored the caller's elapsed interval. | The ingress uses try_lock with repeated original-deadline and signed-expiry checks, including immediately after acquiring the owner. |
| Signature charging or synchronous verification could cross expiry before Begin or cached replay. | Checks bracket charging and verification, and cached response release checks live authority. An already spent attempt is not refunded. |
| A new witness exchange could restart time accounting. | Three charge calls and Begin forward the original absolute deadline and a live callback. Current and CAS cap each exchange by the earlier of that deadline and their own 250 ms ceiling. |
| Returning early on cancellation could discard the outcome of work already performed. | Finish retains its completion path. The final live check can suppress a late successful reply after the actual outcome was persisted. |
| Preparing/signing a witness request could time out before any transport call yet permanently poison the client. | Request preparation, signing and the final pre-send deadline check are outside the uncertainty latch. The latch begins when transport exchange is entered. |
| The guarded-store wrapper could undo that distinction by latching every Current error. | Current's error propagates without an unconditional second latch. Local checkpoint, authenticated predecessor or protected-root integrity failures still latch. |
| The initial socket-timeout argument was disproved by an actual slow-write failure: one progressing blocking write overran its original deadline. | The follow-up uses per-call nonblocking recv/send with the same absolute deadline and bounded would-block retry waits. Descriptor flags and socket timeout settings are unchanged. Complete received CAS evidence remains available for authenticated late reconciliation. |
| A valid matching CAS receipt could be discarded after verification crossed the deadline. | The authenticated matching checkpoint is returned as known success. The guarded local transaction commits before reporting a late live-use error. Missing or unauthenticated results remain uncertain. |
| Retirement could commit and then miss publishing the in-memory epoch because a late callback returned an error. | The epoch is invalidated on either commit outcome before propagating the result. The accompanying store test checks status, highest sequence and epoch. |
| A pathname replacement could separate the locked descriptor from the database path. | Existing opens do not create missing files; descriptor/path and parent identities are retained and checked, with no-follow and ownership restrictions. This is a source-reviewed boundary, not a malicious-kernel guarantee. |
| Client failure stopped later Finish but left already-issued Execute epochs live after an uncertain revocation CAS. | Begin failure exits and Mutation destruction publish terminal epoch zero whenever the client is actually unavailable. Known pre-send cancellation preserves the epoch. A directed test obtains Execute, loses a successful revocation CAS reply, and checks both cancellation and the external/local split. |
| Retirement could overwrite terminal zero with a precomputed positive epoch. | Its atomic update now preserves zero. A separate lost-retirement-CAS test checks zero, the unchanged local pending state, the advanced external checkpoint, and refusal of subsequent Begin. The existing healthy-client late-callback test still requires epoch advancement. |
| File mode alone did not establish trusted ownership. | The database and parent are checked against the effective UID, with no group/other database access and no group/other parent write access. Creation uses mode 0600; the existing-file check is not an exact-equality check against 0600. |
| Schema text was collected into arbitrary Rust Strings before rejection. | The independent witness now requires exactly its one table and checks storage classes, byte widths and exact SQL equality through scalar SQL results. No name/SQL String collection remains. This does not establish an allocation bound for SQLite's own schema parser. |
| Corrupt fixed-width local or external BLOBs could be copied before validation. | The witness guard checks local metadata, checkpoint and protected-row classes and lengths in SQL before materializing or hashing them. |

The six core tests exercise post-sign pre-send cancellation with zero exchanges
and subsequent success on the same client; extra SQLite schema objects and
oversized SQL rejection; the same signing keys under a different binding
generation; matching late CAS success; and separate slow-drip read/write
controls. The signing cut is inside the actual request path. At the initial review stage, these names and source existed without current
execution evidence. Actual results and the write counterexample are recorded
in the final section below.

The store tests additionally cover old complete Node snapshots, lost CAS
replies, local commit failure, stale signed replies, explicit guarded opening,
missing external state, pending/cached permission reads, binding and generation
mismatches, exact retry versus a forked CAS, path replacement, and late
retirement. Their final runtime results belong in the integration command
records, not in an inferred historical test count.

## Cold-open integration finding and source closure

Review of the integrating store.rs identified a cold-open read of
pq_network_owner_v2 into Option<Vec<u8>> before the later guard checked its
width. The integrating owner added witness_metadata_matches: SQL predicates
compare the storage class, expected byte length and exact bytes, returning a
scalar rather than an arbitrary stored Vec. Its absent-value branch detects
unexpected presence without materializing the value.

The guarded PqWitnessV4 cold-open branches now use that helper for the network
policy, witness binding, operator marker and fixed schema/parameters/genesis
pins. This was re-read in the integrating source. The new store negative test
corrupts five stored metadata values and then performs an explicit exact-value
operator repair; its execution remains part of final candidate validation.
This scoped source correction is not a general proof that every legacy
metadata read, schema parser or SQLite allocation is bounded.

The guard itself runs during open before ordinary ledger validation and
recovery continuation. Cached and pending authority is checked under the same
SQLite IMMEDIATE transaction as the fresh authenticated predecessor.

## Remaining security limits

The external root covers exactly the PNQ2 resource, peer and request tables.
It is not an authenticated checkpoint of accounts, History, model installation,
CURRENT, FinalUse, work, or every Node table. A whole old Node snapshot with an
older protected checkpoint is a different attack from selective rollback of
unprotected state. Tests of the former do not certify the latter.

Current is a fresh observation, not a distributed lease. Multiple cloned
databases or duplicated writer credentials can observe the same pending
permission before one advances the external checkpoint. A later conflicting
CAS refusal does not erase a business effect already performed by a clone.
Independent retention of the witness, pinned binding, writer credential and
trusted binary remains a deployment premise.

A failure after transport entry may leave an unread response or an uncertain
CAS, so this implementation disables that client. The pre-send recovery test
does not promise automatic resynchronization after partial I/O. A missing
witness is not implicitly enrolled; opening old local state does not synthesize
an external advance. Recovery from an uncertain external/local split remains
an explicit operational matter.

Synchronous SQLite, hashing and ML-DSA calls are not hard-preemptible. Polling
and deadline checks bound permission to continue at checked boundaries; they
do not prove a CPU or I/O instruction stopped at the exact deadline. Finish
preserves actual completed outcomes and has no separately proven aggregate
tail deadline.

The PNQ2 service remains a constrained loopback protocol carrying signed
plaintext. This work does not qualify sustained public load, WAN operation,
confidential Cell/task data, independent administration, or all Hepta flows.
No STARK parameter qualification, W1 reversible implementation, quantum work
cost proof or difficulty/fork-security proof was added here. The whole-chain
claim gates therefore remain HOLD.

## Primary references and interpretation

[FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) defines ML-KEM for establishing
shared secret key material. [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
defines ML-DSA digital signatures. Those roles do not make signing equivalent
to confidentiality, or key encapsulation equivalent to peer identity.

[NIST SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final), finalized in
September 2025, addresses the surrounding KEM protocol. Section 4.2 requires
assurance of ownership for a peer's static encapsulation key; section 5.2.3
illustrates authenticated ephemeral establishment with a signed transcript.
This supports evaluating identity binding, negotiation and confidentiality
separately.

[Bailey and Sattath, arXiv:2403.08023v2](https://arxiv.org/html/2403.08023v2)
analyze the mismatch between difficulty-weighted chain selection and Grover
search cost in a simplified random-oracle model. Their model omits constants
and treats search success in an idealized way; a later variant respects bounded
difficulty changes. Their result motivates review of difficulty and fork
selection. It is not an implementation of Trillionnium W1, a demonstration
against this chain, or a quantum-cost lower bound for its concrete work.

## Actual combined native result and I/O follow-up

The earlier component hashes above identify the reconstructed source before this
follow-up. Actual local commit `444ae3ed6d3951396dc421e7b26548191962ef9f`
(tree `b4d4cca6da8244cf9c7d479eca0974559f4a1005`, identical to remote
`d2fabdd3757b89db84763d632aeedfe84f9fce4f`) ran all 37 meaningful controls:
36 passed and `slow_drip_write_obeys_one_absolute_deadline` failed. The 40 ms
budget, 8 MiB payload and 500 ms assertion were not relaxed. Complete raw
[source and execution records](../../evidence/pon-pq-system-continuation-20261101/README.md)
preserve this counterexample and the positive store/process effects.

Two internal source reviews checked the follow-up against the actual locked
Rustix 1.1.4 API: per-call DONTWAIT avoids changes shared by cloned descriptors,
EINTR/EAGAIN do not renew time, and complete-read/late-CAS and uncertain-write
semantics remain in place. Only the Node-local net feature is added; no package
version, lockfile, optimization, debug/overflow or business budget is changed.
This source review does not certify the new native execution.
