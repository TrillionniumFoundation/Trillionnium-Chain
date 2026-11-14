# PublicPolicy prefix cache: independent static review

## Conclusion

No substantive framing-equivalence or clone-isolation defect was found in the fixed 16,945-byte patch (SHA-256 519f7b6950743386f53e655edf5e31d3f198de581c7125461a08b28d81211a37). No source correction is requested by this review. This conclusion covers the exact reconstructed candidate bytes, not a full repository proof or a measured repair of the original four-second confirmation failure.

The source checkpoint is M8 `ed0d35487f2a67239e4d646fd41c2c7acb5cc740`, tree `1aa9c21812489080980bdc3c1c2bb43611e88354`. The immutable original PublicV3 blob is `b9bbe75b8509eaf10a73b50aab7e7892f6796e64`, 433,736 bytes, SHA-256 1a90c3eebf8a8642264f8a65ef906f5bdb9c1e656fab8650dc028328f104fb70. Strict in-memory application of all four diff hunks reconstructed 438,782 bytes with SHA-256 0fd32665f5a666af27d8650214cdfd956d1efb5f72927a003ff0b7c84d10f49a, exactly the author's pinned candidate. No worktree was edited.

## Exact input equivalence

The actual original chain is PublicV3's imported `super::hash`, `ingress.rs:25`, and `trnm_protocol::pon_wire::hash` at original lines 19–29. The helper uses the same 10-byte NUL-terminated magic, little-endian u16 tag length, tag, and little-endian u32 length before every part. It preserves the original profile and 5,027-byte r20 resource literal. That literal is byte-for-byte equal; SHA-256 is `624232b02e70ecbb1a2d80972a40aafefe63f12a8fc02d70a61112b6a6b42caf`.

All six suffixes remain in the original order and widths: bits (1), lifetime_ms (8), burst_ns (8), refill_ns_per_second (8), start_reserve_ns (8), and workers cast to u32 (4). Their six length prefixes add 24 bytes, for 61 framed suffix bytes. The original cast and all source constant values remain unchanged.

`OnceLock<Sha256>` stores an **unfinalized** hash state after immutable bytes only. The initializer captures no policy value, nonce, identity, permission, Host observation, deadline, verification result or dynamic part. Every call clones that state, retaining its byte count and buffered partial block, appends all six suffixes, and finalizes only its private clone. There is no shared mutable per-call digest or trust cache. Initialization is bounded pure hashing and has no external I/O or recursive call to this initializer.

The constructor and its error order are unchanged. The four hunks import OnceLock, introduce the unchanged literal/private helper, replace the pure id body, and add tests. Nonce solving, signatures, server validation, Host/progress checks, absolute deadlines, worker/quota/accounting parameters, scheduling and serialized protocol contract bytes are not changed by this diff. Timing and actual CPU charged can naturally differ because the purpose is to avoid repeated pure work; this is not a promise of timing equivalence.

## Tests and evidence limits

The fixed file retains its 84 original textual `#[test]` declarations and adds three. This is declaration/source comparison, not a rustc AST claim or a claim that 87 tests were executed.

The new public-field test compares 56 boundary combinations with the original complete hash function. The suffix test checks nine cases, including an independent change of each of the six fields, all zero values and maximum values. The four-thread test performs 32 differing policies per thread and checks the original development golden afterward.

The reference helper calls the original full `pon_wire::hash`, so it is independent of the new manual prefix implementation. It shares PROFILE and the resource constant with production. Its equality assertions alone would not detect both sides changing that shared literal. The separate original/new byte comparison and unchanged preexisting golden test supply that missing independent evidence. The original golden remains `59ee63889ec8f95e2bd6c45789bf7b5ff3b916cf1244a4970f8744ee49bb175b`, with its three old-profile rejections intact.

The global OnceLock may already be warm before the concurrent test. The test expresses clone isolation; it does not guarantee simultaneous cold initialization or instrumented contention. Root's separately reported serial `RUST_TEST_THREADS=1` run and later default-harness followup must remain distinct receipts. This reviewer did not execute either run, any test/helper, Clippy or benchmark.

Manual duplication of the wire hash framing is a maintenance coupling: future magic/tag/length-grammar changes must receive an explicit protocol review and retain the independent complete-hash and fixed-vector controls. No additional implementation change is required solely by that observation.

## Production path and frequency

The original production server's cookie construction (line 855), context validation (line 893) and signed response creation (line 1007) call `resource_profile()`. Its actual definition is in `public_v3/work_arithmetic.rs:52–61`; the ordinary branch returns `self.policy.id()`. `growth.rs:17–24` independently shows the ordinary client's Legacy dispatch to the same method. Separate growth/PQ/arithmetic profile derivations remain separate and unchanged.

The lexical `.id()` context file also includes Cookie IDs; it must not be misrepresented as a semantic policy-ID call graph. The actual dispatch closure is captured separately in `production-profile-dispatch-closure.json`.

Existing original C0 cross-cost analysis provides these source-derived service-lifetime lower bounds:

| Original pressure trace | Issued challenges | Spent reservations | Delivered response frames | Policy-ID call lower bound |
|---|---:|---:|---:|---:|
| x64 | 370 | 369 | 360 | 1,099 |
| arm64 | 524 | 519 | 510 | 1,553 |

These use three distinct server stages, are not direct invocation instrumentation, may include shutdown tail, and are not an exact four-second interval. **The 1,099 x64 policy-call lower bound is not the separate 1,099 fresh Host checks of one completed W1 verification.** The full original reports are referenced by their existing archived paths and hashes; they were not recopied.

The immutable framed prefix is 5,105 bytes: 79 complete SHA-256 blocks plus a 49-byte buffered tail. The original 5,166-byte preimage takes 81 padded blocks; a later cloned state needs two final blocks. These are structural block counts, not CPU or wall-time measurements. Cold initialization, cloning, SHA acceleration and altered closed-loop attacker throughput matter. No current evidence converts the avoided hash work into a four-second success guarantee.

The hash-use tool's 19 uses and 31 selected inputs do not include PublicV3. Its pass cannot be cited as coverage of this helper or a complete call graph.

## Scope and preserved inspection record

Only fixed Rust bytes, bounded immutable Git reads and closed earlier trace analysis were used. Git lazy fetch and optional locks were disabled. No source, refs, Git objects, stage, environment, test budgets or remote state was modified. New files are independent review evidence only.

One read-only extraction first expected the resource_profile definition in growth.rs and ended with an assertion after capturing that immutable file. Its terminal is preserved. A bounded immutable symbol lookup then located the actual definition in work_arithmetic.rs and closed the dispatch chain. This was an inspection-selector failure, not a candidate test failure.

Current-source binding changes remain the implementation owner's task. The old proposal's active-default PQ21 mapping advice predates M8's explicit frozen/current separation and is not applied here.

`review.json` contains the structured decision. `INPUTS_INDEX.json` fixes the 14 selected local source/proof captures and bounded prior references. `EVIDENCE_INDEX.json` fixes this review's files; `seal.json` binds that index. Full old reports remain references, not duplicate payload.
