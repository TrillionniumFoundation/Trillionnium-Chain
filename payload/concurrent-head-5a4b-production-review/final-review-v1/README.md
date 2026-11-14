# Incoming N production and source-binding review

## Fixed scope and result

This is a read-only comparison of C0 `dc42ce4df5cff79cc61c5addbaf01074b56b06ca` against incoming N `5a4b7fe8de1adce803184f262fd9f704ead1930c`, with root M6 `2a62061177852dc3ebd200fa8d7c66c661a119a1` as an additional immutable comparison. C0 to N changes 49 paths. Only two are Rust source: Node store (+5/-4) and worker audit artifact (+48/-1, including two new tests). CI/workflows/tests are independently assigned to ci_repairs.

Root independently read the full Rust patch and contexts and selected the entire C0/M6 store body plus the independent N worker metadata-baseline tightening, including its two new controls. The incoming store reorderings are not selected. ci_repairs owns the explicit proposal for frozen/current proof namespace compatibility and actual-store workflow pins. No wholesale incoming-side merge is appropriate. No code change, attack or runtime test was made by this review, and no claim is made that N is a deployed vulnerability.

## Store ordering changes

### Readiness before the epoch leaves a narrower observation boundary

N calls ready() at store.rs:6862 before admission_state_epoch() at 6868. ready() reads namespace and the reorg row; read_active repeats namespace and validates active state but does not repeat the reorg check. active()/slot() are direct SQL metadata reads. The final condition compares active tip/generation and the sampled epoch.

A concrete static interleaving is: ready succeeds; an independent SQLite connection commits reorg.done=0 without changing active state; the new epoch sample observes that already completed commit; later reads and the final epoch agree. The reorg marker can therefore be missed. C0/M6 sample the epoch before ready, so the same change either reaches ready or changes the final epoch. This concerns the documented independent-SQLite-connection fence, not a claim that a cooperating writer can bypass the Node owner. It has not been reproduced by a test in this assignment.

### Time deferral changes retained-corruption priority

N moves TIME_DEFERRED to the start of the per-link closure, before required-work arithmetic and cumulative retained-work equality. A valid encoded/header-ID-bound retained block may be future-dated relative to the supplied observation clock while its SQL cumulative chainwork is corrupt. Header-projection validation can pass in that combination. C0/M6 reach the local corruption check first; N returns TIME_DEFERRED first.

error.rs classifies TIME_DEFERRED as StaleContext with requires_owner_stop=false. The retained chainwork errors are LocalStructure and require owner stop. Both versions refuse the request; this finding does not claim a successful confirmation of that damaged chain. Earlier header-projection checks remain active. The difference is a typed error/owner-stop contract, derived statically without executing an attack or test.

The original native_node healthy-chain tests demand TIME_DEFERRED for an earlier observation time. They do not require that result to win over simultaneous retained chainwork corruption. The unchanged confirmation_chainwork tests demand LocalStructure and owner-stop for retained corruption. N adds no Node confirmation Rust tests. Its added source comment asks to preserve namespace/reorg refusal precedence, but no new explicit dual-failure priority or narrow-window test was found in this delta.

Keeping C0/M6 store blob `d596dc6bab16698cd18bcc15bcbbe1fafedf603e`, 391,470 B, SHA256 `5918270368c61b420d26910dc5934714e1423f71c686b2d01f8d2e3ccceb990c`, preserves both relevant baseline orderings. The recent acceptance workflow must bind that actual blob if this selection is made.

## Independent worker tightening

The worker artifact reader currently validates one metadata snapshot but, in C0/M6, establishes its comparison baseline from a second metadata read after acquiring the shared lock. N uses the original validated metadata for that baseline, so permission/hardlink changes between validation and lock cannot silently redefine the accepted identity. A private after-validation test hook and two controls exercise the interval.

NOFOLLOW/NONBLOCK/CLOEXEC, local owner, regular single-link file, non-writability by other users, nonblocking shared flock, before/after named and FD identity, bounded read/line size, UTF-8 and exact length requirements remain. The path grants neither execution nor journal authority and has no dependency on the store ordering changes. The full patch and new tests were read, but not run here.

## Proof and source binding impact

Static inspection of exact N blobs gives authority44 44/44, current lifetime20 20/20, and new PQ current21 21/21 matches. These are selected-map byte checks only. N's hash-use31 map has six mismatches: proof-profile descriptor, pon_work, DA cell.rs, DA cell/store.rs, Node lib.rs and Node store.rs. In particular, its new descriptor expectation is 03dea456..., while the actual N descriptor remains SHA256 797eaa3a... (blob 7714b037...). The full expected/actual rows are retained.

N also introduces a separate current-v2 PQ21 correspondence over the frozen 0f9 V1 model/lock, then switches composition to a current-v3 manifest that retains the old v2 identity. Root M6 instead uses the independently reviewed active-default current mappings. The strict N adapter would reject M6's changed default model/lock; combining the reader and default configurations mechanically is invalid. An explicit namespace decision is required. Existing composition mathematical helpers are AST-identical; the changed methods are routing/default/validation methods. HOLD, null bounds and false activation/qualification remain enforced.

N's authority/current lifetime maps select fc39da5f and the incoming store body. If the baseline store is retained, these N bindings cannot be copied unchanged. The six-crate QROM mapping is not changed by this two-Rust-path delta; no new proof or performance qualification is inferred. The distributed source inventory already contains both source paths using include_bytes; it does not freeze their per-entry byte digests.

## Evidence and boundaries

inventory.json records exact commits, trees, root head/status and changed paths. source-capture-v1/C0-N-full.stdout preserves the full bounded 304,752 B diff. C0-N-rust.stdout preserves the entire two-file Rust diff with 30-line context. All selected raw Git blobs include object-ID and SHA-256 verification. context-v1, context-v2, confirmation-contract-review-v1 and readiness-last-calls-v1 retain function/caller/error/test evidence. declared-source-check-v1 has all selected map comparisons; proof-delta-v1 has JSON and function AST differences.

All Git commands used GIT_NO_LAZY_FETCH=1 and GIT_OPTIONAL_LOCKS=0. Source, refs, config, execution stage and network were not mutated. No tests, native workloads, source-controlled readers or helpers were executed. This is a bounded delta review, not a new whole repository semantic audit, a cryptographic attestation, or an asserted four-second performance fix.
