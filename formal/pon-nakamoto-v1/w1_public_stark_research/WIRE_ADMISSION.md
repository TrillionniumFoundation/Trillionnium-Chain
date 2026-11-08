# Fixed W1 proof wire admission

This continuation of commit `3bbd072e4983eceee4531d7576d329da5b0d0900`
adds an allocation-free check of the complete, fixed P3 0.8.0 proof encoding
before the allocation-owning decoder or statement preprocessing runs.
Qualification remains **HOLD_NO_GO**.

The retained two proof components, AIRs, commitments, field, 64 FRI queries,
Fiat–Shamir transcript, statement and independently supplied expected inputs
are unchanged. Wire admission is not a proof verifier. A canonical value
mutation with the correct shape still reaches the original cryptographic
verifier, including its late rejection paths.

## What is checked before decoding

The caller selects SHA or arithmetic; the proof cannot choose its profile.
The scanner checks the application magic, every fixed vector length, all
five Option tags, canonical Goldilocks encodings, the complete input-opening
matrix shapes, binary-fold query/sibling counts, the final polynomial length,
the degree, and end of input. Each Merkle multiproof has a variable number of
boundary digests, bounded by the sum of all unpruned binary paths. Exact
transcript-dependent frontier authentication remains with P3.

Both proof buffers must pass before either is deserialized. The file reader
uses the component limit before allocating the encoded buffer. The public
statement keeps its existing exact 377,290-byte limit. Admission does not
load, accept or cache a caller-supplied preprocessing key.

| Frozen shape | SHA | Arithmetic |
| --- | ---: | ---: |
| Trace degree bits / FRI fold rounds | 13 | 17 |
| Main trace width | 7,728 | 516 |
| Preprocessed width | 27 | 18 |
| Quotient chunks, each width 2 over the base field | 2 | 1 |
| Input commitment batches | 3 | 3 |
| Queries per input batch and fold | 64 | 64 |
| Fixed vector headers | 1,338 | 1,540 |
| Maximum Merkle boundary digests | 9,536 | 14,528 |
| Maximum base-field words scanned | 567,436 | 95,762 |
| Minimum syntactic envelope bytes | 4,245,061 | 313,541 |
| Maximum admitted envelope bytes | **4,550,213** | **778,437** |

The minimum is a syntactic count with empty authentication frontiers, not a
claim that a valid proof attains it. The maximum is conservative: pruning
usually needs fewer digests. The pair plus statement is at most
**5,705,940 encoded bytes**. This replaces the former separate 64 MiB input
limits on the verification path; it is not a bound on the verifier's complete
heap, process RSS, thread stacks, preprocessing or runtime.

## Derivation of the structural bound

Let `r` be the component degree bits, `q = 64` and `b = 2` the log blowup.
All three input batches have height `2^(r+b)`, and use a cap of height zero.
Opening one leaf in a binary tree of log height `h` needs at most `h`
siblings. A pruned multiproof cannot need more siblings than the union of
the `q` complete paths. Thus the three input frontiers have at most

`3 q (r+b)`

digests. Fold `j`, numbered from zero, commits a codeword of log height
`r+b-j-1`. All its queries need at most `q(r+b-j-1)` digests. Summing gives

`q [r(r+b-1) - r(r-1)/2]`.

Adding both expressions gives 9,536 and 14,528. Each digest is four
canonical 8-byte base-field elements. Every extension-field element is two
such elements. All other cardinalities are fixed by the table and the pinned
P3 type layout. The scanner uses checked slices, validates a vector's length
before entering its body, and checks each variable path length against its
constant bound before conversion or multiplication.

For either accepted or rejected input, the scanner traverses at most the
component's maximum field-word count, its fixed vector-header count, five
Option tags, the degree word and magic. Rejection can stop earlier. No field
value causes a hash computation, FFT, AIR construction, recursion, allocation
or data-dependent unbounded loop in this scanner. The code contains no
`Vec`, owned string, boxed object or recursive call. The allocator-observation
test independently checks calls during scanning on the actual retained proofs
and malformed inputs.

This is a source-level structural operation bound for this exact scanner.
It assumes ordinary correct Rust/library execution; it does not translate
those operations into an absolute physical time or energy bound.

## Tests and measurements

[The native tests](tests/wire_admission.rs) use the two complete retained
proofs, not a synthetic successful proof. They pin canonical round-trip
encoding, exercise huge length words, Option and field encodings, truncation,
component confusion, OOD widths, FRI counts, both frontier limits, final
polynomial size and degree. Correctly shaped wrong field values remain
admissible syntax and require the real verifier.

[The measured comparison](run_wire_admission_campaign.py) runs the old pinned
binary and the candidate against exactly the same typed malformed proofs.
Its three ABBA blocks per shape retain every process and use process wall
boundaries. It reuses historical proof bytes and explicitly generates zero
new proofs. It checks that each candidate refusal precedes preprocessing,
while the original binary actually reaches its original preprocessing stage.
Its source and binary bindings are checked before and after measurement.

The recorded 2026-11-08 native campaign completed 3 positive full verifications
and all 96 rejection processes, with 6 observations per binary per shape.
All positive verifications rebuilt preprocessing independently; their outer
wall times were 1.014997, 1.023839 and 1.001955 seconds. Their admitted field-word
counts were 543,172 / 64,818 and Merkle boundary counts 3,470 / 6,792.
These are historical-proof replays with the successor verifier, not fresh
proof generation. The shared host was not a production resource qualification.

| Changed component / shape | Original median seconds | Admission median seconds |
| --- | ---: | ---: |
| SHA / short trace opening | 0.144646 | 0.008247 |
| SHA / short last input row | 0.338870 | 0.009747 |
| SHA / extra last-fold query | 0.154228 | 0.009901 |
| SHA / extra final coefficient | 0.149461 | 0.009297 |
| Arithmetic / short trace opening | 0.907329 | 0.009767 |
| Arithmetic / short last input row | 0.978076 | 0.010458 |
| Arithmetic / extra last-fold query | 0.926908 | 0.010718 |
| Arithmetic / extra final coefficient | 0.929630 | 0.010920 |

The exact binary, retained proof, source, log and per-process resource hashes
are preserved in `evidence/round3-wire/`. Before/after source and binary
bindings matched. The initial focused native checks passed 18 original unit,
3 original proof smoke and 13 new wire tests, with locked/offline metadata,
formatting, all-target build and strict Clippy. Later integrated checks have
separate exact-source receipts; the earlier observations are not relabeled.

The original [ordinary controls](run_campaign.py) and
[late-FRI controls](run_late_controls.py) remain independently required.
[The successor replay](run_successor_controls.py) reproduces those controls
while explicitly recording that the proof producer and current verifier
have different binaries; it never edits the original generation receipt.
The successor replay completed one full positive, all 11 ordinary controls,
and all four typed late controls; the latter retained FinalPolyMismatch and
CommitPhaseMmcsError(CapMismatch), with no shape rejection substituted.

Structural rejection must not be substituted for their canonical value or
last-fold authentication mutations.

## Remaining production obligation

The global malicious-rejection gate still needs an admitted production
Node path and one complete resource owner covering input receipt, queueing,
authentication, parsing, preprocessing, cryptographic verification,
cancellation, response and cleanup. Resource observations must include all
concurrent work and retain failed or unfinished attempts. The original
0.25-core, 2-GiB, zero-swap, 256-PID and four-second/16-hostile contract is
unchanged. A finite malformed-shape benchmark does not prove the maximum
over all valid-shape malicious proofs, all schedules or all storage behavior.

This change neither establishes the complete noninteractive/quantum proof
nor a cheapest-legal-strategy physical-work bound. It adds no production
proof dispatch, chainwork, deployment, merge approval or activation.


## Integrated carry profiles

The later integration registers two additional caller-selected fixed profiles.
It retains the earlier component-1/2 campaign and its exact source identity.
Both new example verifiers now scan both immutable buffers before either
decode, with the same zero-allocation scanner and original cryptographic checks.

| Field | Carry component 3 | Packed component 4 |
|---|---:|---:|
| Magic | W1P3ACR2 | W1P3APC3 |
| Degree bits | 17 | 14 |
| Main / preprocessed width | 74 / 36 | 370 / 180 |
| Quotient chunks | 1 | 1 |
| Next-row openings | none | none |
| Fixed vector headers | 1,540 | 1,339 |
| Maximum frontier digests | 14,528 | 10,688 |
| Maximum field words | 67,778 | 81,059 |
| Minimum syntactic bytes | 89,669 | 317,189 |
| Maximum envelope bytes | 554,565 | 659,205 |

The paired SHA limit is unchanged. Pair plus public statement caps are
5,482,068 / 5,586,708 bytes. The fifteen native wire tests include real full
proof fixtures for all four profiles and all pairwise profile confusion.
[Carry controls](run_carry_controls.py) passed two complete positives, 22
ordinary negatives, four typed late negatives and eight shape negatives.
These 36 fresh verifier processes reused pinned historical proofs; no proof
generation is implied. Four separately generated full guarded ABBA samples
also verified. See [the complete round report](ROUND3_REPORT.md).
