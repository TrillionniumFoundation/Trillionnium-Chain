# Whole-chain PQ composition candidate, 2026-11-08

Status: **HOLD / NO-GO for whole-chain PQ and production activation**.
This continuation composes fixed source, closes two bounded implementation
gaps, and records new exact-source tests. Source integration, a successful
payload readback, and an honest hash-call ledger do not supply a whole-chain
security theorem or FinalUse authority.

## Fixed inputs

The base is PR #812 at
`7e044b65454f4c9ea505591727332acffb33e7e5`. The following exact heads are
retained as real Git merge parents, not just copied patches:

| PR | Exact head | Added scope |
| --- | --- | --- |
| #799 | `d0a567658ae907ad51e45538b90130402c79a3d0` | Reject classical local owners before effects; retain source traces and controls |
| #800 | `f63890781e21f65e3779f3a6f1ce27aaaa804b94` | Authenticated loader bytes and static M15 closure controls |
| #801 | `50a1fad7156dedd7db31f08a4bb1c94cc0c9d015` | M12 independent recovery checkpoint fencing |
| #803 | `ebc31f07f96060fe1e9fb165aae0123de0fcbc1a` | Actual P3 pruned mixed-height MMCS two-opening binding reduction |
| #798 | `a49bcd0c1f88cacf35421208977df3ae9d9df3af` | Fixed RISC Zero AIR, DEEP and FRI algebra replay |
| #806 | `0788c44f4139c74772a8a9d7d475821f56e5b727` | Lifetime budget, curated effect register and dual-family root policy model |

Earlier evidence remains historical evidence for its own source. In particular,
the original 32/45-command campaign and its fixed 52-control release roster are
not silently replaced by this candidate's different roster. The original P3
runner's unchanged-runtime-scope assertion is retained. Its refusal on changed
integrated runtime source is not a failed cryptographic proof or permission to
weaken the assertion.

## Complete content binding reaches cached materialization

[`materialize_cached_payload`](../../trillionnium/crates/trnm-data-availability/src/cell/content_v2/cached.rs)
first verifies an independently supplied complete TCM2 manifest claim. It checks
the TCM1 transport family, five dependency locators and payload length against
that manifest. TCM1's SHA-256 identifiers locate disposable cache rows; they do
not replace the complete CCH1 payload commitment.

The method sends each owned chunk buffer both to the staged output and to the
existing SHA-512 content observer. It does not reopen the cache to hash a
different stream. The cumulative manifest and payload budgets include EOF;
reservations precede output creation and cache reads and are not refunded.
The original absolute deadline is carried through cache reads, writes, sync,
and the final no-replace publication check. The full legacy transport digest
is also checked at EOF as a consistency condition.

Sixteen new regression cases cover independent pins, same-size stale content,
transport mismatch, corrupt/missing cache rows, output conflicts, cumulative
budget and deadline refusal, cleanup, and budget-before-output ordering. They
retain the existing nonempty-payload format rather than changing its namespace.

The caller must control the output directory against concurrent mutation.
Failed cache reads may remove corrupt disposable cache rows. Once publication
begins, durability and cleanup finish; a later I/O error can leave a complete
output without a successful readback. This is a cooperative deadline, not
preemption of blocking filesystem calls. The returned private readback covers
one payload. It does not freeze later bytes, prove TCC2 dependency closure,
authenticate the supplied pin, or authorize installation, CURRENT, a live
loader, recovery or FinalUse.

## MMCS call lengths have an explicit accounting unit

The [MMCS sponge accounting contract](../../formal/pon-nakamoto-v1/p3_shared_primitive_qualification/pruned_mmcs/SPONGE_ACCOUNTING.md)
records every observed call before digest deduplication, including repeated
messages. It distinguishes native cached-prefix evaluation, native full-message
collision-witness rechecks, and deliberately artificial test-oracle overrides.
For SHA3-512's 72-byte rate, a complete framed message of length `m` contributes
`floor(m / 72) + 1` equivalent padded absorption blocks. The complete frame
includes its header and eight-byte length suffix.

These are message-length equivalents, not measured Keccak permutation calls.
Only cases that explicitly expose a `verification_sponge_accounting` ledger
and successful witness rechecks are covered. Extension/base parity, path
reconstruction, prefix initialization, other controls and failed processes are
outside that ledger. The independently implemented Python reader recomputes
the frame arithmetic and refuses invented telemetry or security claims.

`native_permutation_telemetry` and `qualified` stay false.
`native_permutation_calls`, `adversary_lifetime_query_budget` and `security_bits`
stay null. Honest verifier accounting does not bound offline, failed,
unpublished, recursive, preprocessing or quantum adversary work. The existing
classical conflicting-opening reduction remains distinct from a quantum
extractor and full PCS/Fiat-Shamir composition.

## Source locks and remaining obligations

Combining the branches changes files covered by the lifetime and curated-effect
locks, as well as the full Rust source inventory. Their initial refusals are
retained. A reviewed rebind must use a full committed revision and its actual
Git blobs, check those bytes against the worktree, retain all selected paths,
anchors and false qualification flags, and record the old and new identities.
It must not relabel an old passing run as execution of the new source.

The root/recovery module remains a policy model over supplied approval claims;
it does not execute the proposed dual-family root signatures. TLS key agreement
does not migrate every account, administrator, release or recovery authority.
The RISC Zero replay checks a fixed seal, not all guest/VM/compiler/AIR semantics
or all recursive programs. P3 still needs its actual commitment extraction,
state-restoration/RBR, shared-oracle, transcript and lifetime assumptions mapped
to applicable quantum theorems. Independent currentness and rollback retention,
deployment custody, full loader consumption and the joint consensus/network
model remain open. No actual whole-chain failure bound is asserted.

The [sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
tracks this continuation. Final commands, source receipts, unsuccessful
observations and scoped results belong to its composition evidence packet.
