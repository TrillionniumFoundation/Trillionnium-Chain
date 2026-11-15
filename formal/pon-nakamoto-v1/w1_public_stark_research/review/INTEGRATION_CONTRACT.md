# Full W1 public STARK: integration contract

## Recovery note and evidence boundary

This document was reconstructed from the independent reviewer's retained context after the local scratch directory was found empty. It is a fresh copy of the reviewed design, not a claim to be a byte-for-byte recovery of the former document. The tested Rust source hashes are recorded below so the restored implementation can be checked against the implementation actually reviewed.

Before the loss, remote job `1a1b62108c7-12894-288` compiled the crate against Plonky3 0.8.0 and Rust 1.95.0. `cargo check --locked --offline --lib --jobs 2` passed; `cargo test --locked --offline --lib --jobs 2` passed **18 tests, 0 failures**. The reviewer independently read the complete stdout, stderr and authoritative job status before the loss. That job did not build the full W1 traces or generate a full W1 proof. Recovered logs, new proof runs and proof-level negative tests must be identified separately.

The qualification remains **HOLD_NO_GO**. A complete concrete noninteractive security bound and production qualification are unresolved.

## 1. Scope and statement

This prototype proves the complete frozen W1 relation with two real Plonky3 AIR/PCS proofs. One proof covers all SHA-256 calls; one covers all field arithmetic. The entire candidate, original prefix trace and intermediate claims are public. The design claims neither zero knowledge nor a succinct public statement.

The verifier receives an independent `Expected` object containing the 318-byte expected header and 64-byte expected artifact commitments. These inputs must come from its caller's independent context; the verifier must not derive its expected values from the candidate it is checking.

The canonical public encoding is exactly **377,290 bytes**:

| Part | Bytes |
|---|---:|
| Codec magic `W1P3PUB1` | 8 |
| Original raw candidate | 49,506 |
| Complete original prefix | 131,072 |
| 515 claimed SHA digests | 16,480 |
| Eleven 64-by-64 arrays of canonical field words | 180,224 |
| Total | 377,290 |

The arithmetic arrays contain E, F, Ahat, Bhat and the first seven AB prefix matrices. The original candidate supplies A, B, C and the original claimed trace digest. SHA claims contain the challenge, all four labels' 128 noise-counter digests, the ticket and work identifier. No independently encoded duplicate of the expected header or expected artifacts is accepted as authority.

## 2. Canonical verifier flow

1. Bound and decode the fixed-size public byte encoding. Reject malformed lengths, magic and noncanonical field words.
2. Call `PublicStatement::plans(&Expected)`. This checks the independent header, canonical words, original prefix indexing, ticket threshold and deterministic rejection selection, then creates both canonical plans from the same public object.
3. Construct the SHA AIR with `W1ShaAir::public_only(&sha_plan)` and the arithmetic AIR from the generated rows.
4. Recompute both preprocessing commitments and verifier keys with the fixed proof configuration and fixed trace heights. Never trust a preprocessing key supplied by the prover as the meaning of the public statement.
5. Check fixed proof shape/degree metadata and verify both proofs with the rebuilt keys. Use a fresh challenger initialized by the fixed configuration for each proof.

`ShaPlan::for_public_messages` is a legitimate generic SHA component/testing factory. It is not the W1 statement factory, and an arbitrary plan constructed with it must never be accepted as a W1 proof. Likewise an arbitrary list of valid dot-product rows is not a W1 proof.

All public parsing, plan construction, preprocessing and verification-key reconstruction time and memory belong in verifier measurements. A cached-key measurement is a different workload and must be named separately.

## 3. Complete original SHA message inventory

The message builder preserves the original domain and framing. The main hash domain is `TRNM-PON1\0`; the original trace domain is `TRNM-PON-TRACE1\0`. Framed hashes use a little-endian u16 tag length and little-endian u32 length for every part. SHA block words and SHA final digest words are big-endian u32 as required by SHA-256. These conventions must not be confused with the little-endian 32-bit noise candidates.

| Message | Original message bytes | Compression blocks | Count | Bound output |
|---|---:|---:|---:|---|
| Artifact A | 16,408 | 257 | 1 | Independent expected artifact A |
| Qualified task input B | 16,423 | 257 | 1 | Independent expected artifact B |
| Task A,B | 32,792 | 513 | 1 | Task field in independent header |
| Challenge(header) | 343 | 6 | 1 | Shared public challenge claim |
| Noise(challenge,label,counter) | 66 | 2 | 512 | Shared public noise claims |
| Original trace-domain, challenge and complete prefix | 131,120 | 2,049 | 1 | Original raw trace digest |
| Ticket(challenge,trace) | 90 | 2 | 1 | Shared ticket claim |
| Block/header work identifier | 375 | 6 | 1 | Shared work-id claim |
| Total | — | **4,114** | **519** | — |

The last row is six compression blocks, not seven: 375 bytes plus SHA padding and length occupy 384 bytes. This was explicitly corrected during the initial review.

The fixed-shape prototype proves all 128 counters for every noise label. The deterministic public selector retains only the first 512 accepted little-endian u32 values per label, in native order, rejecting words at least `q = 2^32 - 5`; it fails if the native 128-counter budget is exhausted. Extra hashes after the native stopping point add proof cost but do not alter the original relation. They do not introduce a new false-rejection condition for otherwise valid native candidates.

## 4. SHA AIR constraints

`W1ShaAir` uses the official `p3-sha256-air = 0.8.0` compression AIR, with **7,728 main columns** and one compression per row. The wrapper adds **27 public preprocessed columns**:

| Columns | Meaning |
|---|---|
| 0 through 15 | The canonical 16 message-block words |
| 16 | FIRST: a message's first compression, or an independent padding row |
| 17 | CHAIN: this compression has a next block in the same message |
| 18 | OUTPUT: the last compression of a real message |
| 19 through 26 | Expected final digest as eight big-endian words |

The wrapper enforces:

- The first 16 official message-schedule words, packed from Boolean bits, equal the canonical public block words. Padding is therefore part of the constrained message.
- FIRST rows have the standard SHA-256 IV in the official 16 input-state limbs.
- CHAIN rows link the output-state bits to the next row's input-state limbs under the transition selector.
- OUTPUT rows pack and match the exact claimed final digest words.

All inner SHA compression constraints are evaluated in addition to these wrapper constraints. Each trace padding row is an independent zero-block compression with a fixed standard IV; it has no output obligation and no chain into another row.

There are 4,114 actual rows, padded to 8,192. The main next-row column declaration contains the 16 input-state limbs; preprocessed next-row access is empty. The degree hint is three. The wrapper exposes no scalar public values because the statement is bound by the reconstructed preprocessing commitment.

`sha2::compress256` is used only to generate honest intermediate compression states. The verifier's `public_only` constructor performs no SHA compression. A host digest equality is not substituted for a SHA constraint.

## 5. Complete arithmetic coverage

The base proof field is Goldilocks `P = 2^64 - 2^32 + 1`. The native field is `q = 2^32 - 5`. Each row has public canonical operands `a[8], b[8], start, goal` and private Boolean quotient/remainder bits.

The main row has **516 bits**: eight 32-bit product quotients, eight 32-bit product residues and one 4-bit sum quotient. The preprocessed row has 18 canonical field elements. Constraints enforce each product equation and the eight-residue sum. Integer bounds prevent Goldilocks wraparound; the full argument and the valid carry-nine example are in `DOT8_516_REVIEW.md`.

| Relation | True rows |
|---|---:|
| E = X Y and F = Z T | 8,192 |
| Ahat = A + E and Bhat = B + F, encoded as dot/add rows | 8,192 |
| All eight noisy product-prefix matrices | 32,768 |
| All eight AB product-prefix matrices, last goal C | 32,768 |
| Total | **81,920** |

The trace pads to 131,072 independent zero rows. E/F, Ahat/Bhat and the first seven AB prefixes are public claims, each checked by these rows. The native factors have the original 64-by-8 and 8-by-64 layouts. The original prefix serialization remains `bi, bj, bk, local_i, local_j`; the factory explicitly maps it to group-major matrix cells and links each predecessor. A different layout is not interchangeable even when it contains the same multiset of words.

Complete noisy multiplication, E/F definitions and the separate exact AB=C check are equivalent to the complete original denoise relation over the native field. They are not a random projection of AB=C and do not use the previous FS-v2 Freivalds checker.

## 6. Memory and performance accounting

These are logical allocation sizes, not observed process peaks:

| Array | Bytes at 8 bytes/base-field cell |
|---|---:|
| SHA main, 8192 by 7728 | 506,462,208 |
| SHA preprocessing, 8192 by 27 | 1,769,472 |
| Arithmetic main, 131072 by 516 | 541,065,216 |
| Arithmetic preprocessing, 131072 by 18 | 18,874,368 |

PCS commitments, LDEs, quotient data, DFT workspaces, prover data, serialized proofs and allocator overhead are additional. The two main traces alone total 1,047,527,424 bytes. Sequential proving can avoid retaining both simultaneously, but a report must measure the actual live allocations and runtime. The component tests never allocate these full traces.

## 7. Tests and integration requirements

The historical 18 passing library tests comprise arithmetic 5, public codec/wiring 3, SHA plan 3 and SHA AIR 7. SHA negatives include wrong IV, broken chaining and wrong padding with otherwise valid individual compression rows, so they exercise message binding beyond the official compression AIR.

The message-plan audit separately compared the canonical messages/digests to the frozen Python reference on five valid fixtures and obtained 4,114 compression blocks in each case. Its detailed JSON was lost with scratch and must be recovered or rerun from the actual fixtures; this reconstructed document does not manufacture those missing case hashes.

The first complete native run has now generated both full W1 proofs, and three fresh verifier processes have accepted the same proof pair after independently rebuilding their preprocessing. Its eleven original negative controls all rejected at the expected component or parser stage. These results are separately identified in `runner_review.json`; they do not retroactively change the scope of the historical component job. Four additional typed late-stage controls are described in `LATE_REJECTION_REVIEW.md`.

A subsequent strict lint check requested an equivalent rewrite of the 16-word SHA message-binding loop. The new code iterates `preprocessed[..16]` with `enumerate`, retaining exactly 16 assertions in the same order and retaining a short-slice panic. The original run's complete SHA source is preserved as `prelint_sha_air.rs.txt`, with its original SHA-256 verified.

The final source now has its own completed full run, `retained-native-02`, under durable job `1a1b875cbb9-12894-f8f`. Format checking, locked/offline metadata, strict all-target/all-feature Clippy, 18 library tests, three real-proof integration tests and the all-target build passed. The doc-test command passed with zero doc tests. Both complete traces and proof components were generated; three fresh verifier processes accepted, all eleven original negative controls rejected at their expected stages, and all four typed later-stage controls returned their precise required rejection variants. The final manifest's 13 source files were matched to local bytes and hashes.

The final binary SHA-256 is `7700eff6ea4a3ff1f8f6551c323ac5b90b2bb5a96d1eaeca41e108bc54a7e3fc`. `runner_review.run02.json` records its sources, actual per-phase observations, evidence hashes and limitations. Run-01 is preserved separately. Statement and proof bytes were observed to retain the same recorded hashes and sizes across the two runs; this was checked after execution, not inferred from source equivalence. None of these successful execution gates closes the concrete noninteractive security or production-resource obligations.

## 8. Historical tested-source identity

| Source | SHA-256 of the version actually reviewed and tested |
|---|---|
| `src/sha_air.rs` | `ccf2f7b52b0ad2a8de95289a1c4f6c3d56b497cd1da9141eb121f0c6bea5a2a5` |
| `src/sha_plan.rs` | `d1db8a58108702548ce801d6c8b558d49f975f72b6461d2d59be7d92c6b3c0d3` |
| `src/arith_air.rs` | `58b449817db1b1f9575d9ce64651469ecfe6d6e4e165db26be2ecef5bada0882` |
| `src/public.rs` | `36e04e65fdeb843e309b688d5203a61a164b3e4d795d8361ea4ea925ce2f8e85` |
| `Cargo.lock` | `9e28bf0b3912ca692b0f80842a3f20323b212b2a1c5bbaa85d7503654c069c2e` |

The frozen W1 source repository commit used for the original relation is `e70f13448aad715286fb8eb56fc802b09db643a3`. The later isolated desktop worktree used for P3 compilation was created at `8df4b21d893906570d48f5beafabb3b31e0aefbc`; it is not a replacement relation definition.

This table identifies the historical restored/component-tested files and is intentionally not rewritten after formatting, the lockfile's direct-dependency update or the later equivalent lint change. `runner_review.json` records each later run's exact source and binary identities. The SHA source preserved in `prelint_sha_air.rs.txt` also reconstructs the SHA module used by the first complete proof run.
