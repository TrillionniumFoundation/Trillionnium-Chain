# PublicPolicy immutable-prefix candidate: source and binding impact

## Decision

This is a qualified implementation proposal, not an implemented optimization or a repair of the original four-second confirmation target. No production file, test, quota, deadline, worker count, signature check, Host check, source mapping or Git object/ref was changed. No native/hosted test or benchmark was run. Root has explicitly deferred implementation pending evidence of value.

The reviewed M5 checkpoint is 08c9becab740ab2c375b970f376a7638f44c9e8e. Its public_v3.rs is blob b9bbe75b8509eaf10a73b50aab7e7892f6796e64, SHA-256 1a90c3eebf8a8642264f8a65ef906f5bdb9c1e656fab8650dc028328f104fb70, identical to the original C0 runtime reviewed here.

## Proposed production scope

PublicPolicy::id rehashes a 5,027-byte fixed r20 resource-contract literal on each call. The original pon_wire::hash framing consists of the ten-byte TRNM-PON1 NUL-terminated magic, a two-byte little-endian tag length, the tag, and a four-byte little-endian length before every part.

The tag, profile and contract form 5,105 immutable framed bytes. The six original dynamic parts, in order, are bits, lifetime milliseconds, burst nanoseconds, refill nanoseconds per second, start-reserve nanoseconds and worker count. Their original individual frames and widths add 61 bytes. The complete 5,166-byte preimage requires 81 SHA-256 compression blocks including padding.

A private OnceLock<Sha256> could retain the unfinalized immutable prefix state. A per-call clone preserves its byte count and buffered 49-byte tail before all six original dynamic parts are appended. It reuses 79 completed blocks and requires two blocks to finish each later call. Using a finalized prefix digest as an input would be incorrect. First-use initialization and cloning also cost time.

Node already declares sha2 = "0.10" at Cargo.toml line 37, and public_v3.rs already imports Digest and Sha256. No dependency or lock change is needed. This proposed cache contains only immutable code constants, never identity, trust, permission, filesystem or verifier results.

The source-derived Python preimage proof compared all 24,713 constructor-domain pairs (bits 8 through 20, lifetime 100 through 2,000 milliseconds), plus six boundary pairs. It checked the original development golden 59ee63889ec8f95e2bd6c45789bf7b5ff3b916cf1244a4970f8744ee49bb175b. This was not Rust execution or timing evidence. A later code proposal still needs independent original-byte/reference vectors and unchanged original golden/refusal controls.

## Original-trace lower bounds

| Original pressure service | issued_challenges | spent_reservations | delivered_response_frames | server policy-ID lower bound |
|---|---:|---:|---:|---:|
| x64 cross-cost | 370 | 369 | 360 | 1,099 |
| arm64 cross-cost | 524 | 519 | 510 | 1,553 |

These three distinct server stages evaluate the ordinary policy ID: cookie creation at public_v3.rs 845–882, Solution context validation at 884–912 before its reservation counter, and signed response creation at 985–1031 before the delivered-response counter. The original fixtures select the classical/default profile. Neither trace records an output-admission or output-serialization refusal.

These are service-lifetime lower bounds, including possible shutdown tail. They are not direct invocation counts or aligned to one exact four-second interval. They omit paid-body validation, client calls and failure paths. The x64 number 1,099 is coincidentally equal to a completed W1 Host checkpoint count; they are different operations.

The lower bounds represent only about 5.61 MB / 7.93 MB of repeated immutable prefix input. Removing those algorithmic hash blocks does not establish a material wall-time gain or confirmation success. No block-to-time conversion is justified.

## Current source-map impact

The exact path/OID/SHA search covered config, scripts, formal, .github, docs/security and docs/development: 47 references in 19 files. Saved raw searches distinguish path inventories, executable readers, current locks and historical observations; this scope is not a full repository semantic audit.

The direct current byte pins are the corpus Git OID and active PQ21 source-lock SHA-256. A real source checkpoint containing the changed Rust bytes must exist before a new mapping names it; those bytes cannot be attributed to M5 or dc42.

| Current file | Necessary follow-up if implementation is selected |
|---|---|
| config/pon/pq128-source-lock-v1.json | One reviewed source SHA-256 and the new actual source revision |
| config/pon/pq128-lifetime-budget-v1.json | Matching experiment.source_revision only |
| config/pon/pq128-lifetime-composition-v2.json | New review context and legacy child manifest SHA/revision |
| scripts/ci/pq_lifetime_composition.py | Corresponding independent REVIEW_BASE / INPUTS literals |
| config/pon/pq-cross-branch-corpus-v1.json | Actual Git OIDs for changed source and consumers; required paths retained |
| Two PQ lifetime/composition documents | Accurate new current mapping/checkpoint description; history preserved |

The composition reader calls the strict lifetime reader and validates both the child manifest SHA and revision. Only replacing the Rust digest is insufficient. Its counts remain 21 legacy / 46 root / 1 shared / 66 union. Root46, authority44, current-lifetime20 and the QROM six-crate source closure do not select public_v3.rs and require no rebind solely for this proposal.

The original lifetime58 and composition60 methods do not hardcode the current dc42 checkpoint/hash and need no assertion relaxation. The independent policy-read test requires the r20 byte literal to appear exactly once in Rust; a prefix extraction must preserve that constraint. Applicability/module/source-set inventories already list the path.

The historical work-cost contract and resource-pressure manifests/results retain their source hashes and status. No old report, probability, assumption, domain, math, quota or false qualification flag is to be refreshed by this proposal.

## Evidence limits

The sibling JSON binds source exports, direct dependency receipt, original reports, pure preimage proof, consumer excerpts and reverse-hash search. No claim of a four-second repair, hosted acceptance, complete reactor CPU coverage or full repository equivalence is made.
