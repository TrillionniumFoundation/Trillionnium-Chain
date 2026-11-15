# W1 fixed-receipt FRI transcript and Merkle-opening replay

## Result and boundary

The fixed historical v2 `succinct.bin` now has a complete **hash-transcript and
Merkle-opening replay**: 69 ordered commit/challenge events, all 50 query indices,
all seven cap reconstructions, and all 350 openings, including 4,050 sibling-node
hashes. The reconstructed code root equals the pinned `join.zkr` control ID.
The seal consumes exactly 55,667 words. The implementation and meaningful
mutation/differential controls are in
[the replay script](../../scripts/w1_fri_query_replay.py) and
[its tests](../../scripts/ci/test_w1_fri_query_replay.py).

This advances the earlier
[encoding-only transcript map](../../scripts/w1_fri_transcript_audit.py), which
did not evaluate Poseidon2, draw the actual challenges, or check openings. It
does **not** verify the AIR validity equation, the DEEP-ALI evaluation, the FRI
folding equations, or terminal polynomial evaluations. Replay follows the
verifier path conditional on those omitted checks succeeding. It does not
verify the complete receipt, every recursive program, or any QROM theorem.
All security, production, and consensus qualifications remain false; quantum
security bits remain null. The
[formal obligations](W1_QROM_FORMAL_OBLIGATIONS_20261107.md) and
[closure continuation](W1_QROM_CLOSURE_CONTINUATION_20261107.md) remain open.

## Exact source and fixture identity

The input profile is `trnm-w1-risc0-3.0.6-poseidon2-join-v2`, as frozen by
[the implementation contract](../../config/pon/w1-qrom-implementation-v1.json)
at project head `0c830e0be8939ce80c8443c9ad68021b87343a00`. Its selected upstream
sources are `risc0/risc0@8c215e2f4ccdd935f0517bf05d90f1ae032840a9`, not a moving
branch or whatever package is currently installed.

The report calls that project revision `input_profile_source_head`: it identifies
the fixed input/profile and helper provenance. It is not the revision at which
this new replay generator was tested. The report separately records
`generator_sha256`; the release manifest identifies the tested source tree.

| Input | Exact identity |
| --- | --- |
| Receipt | `evidence/pon-w1-full-v2-20261105/succinct.bin`, 257,014 bytes |
| Receipt SHA-256 | `6c72828c9d05a62175e08fa3e7e1d0d5e85e785ad96b5beb5ec7a2e2490c26ee` |
| Seal | Starts at receipt byte 12; 55,667 little-endian `u32` words; 222,668 bytes |
| Seal SHA-256 | `5db567c375823939177220fe12beb9df29ca032d3f5c64adcce8c60d04679619` |
| Source snapshot | [24 selected files plus their recorded metadata](../../evidence/pon-w1-qrom-implementation-20261107/upstream-sources.json.gz), 69,332 compressed bytes |
| Source snapshot SHA-256 | `f6be3667106df6843f5f29c0954cdce8e2617da36c9c91a7a5198665675e0253` |

The script verifies the snapshot's exact compressed identity, each member's
length/SHA-256/Git-blob identity, fixed commit and source URL, and the source
pins used by both existing helpers. It compiles the exact hash-checked local
helper bytes; it does not import a same-named search-path or cached module and
does not execute upstream Rust source. The full receipt SHA-256 is checked
after replay. This ordering lets canonical mutation controls reach the actual
hash/path checks. A change invisible to this partial replay, including a
change to the opaque outer suffix, still cannot yield a successful report for
the frozen receipt. The outer suffix is not semantically decoded here.

## Representation boundaries

The field is BabyBear, `p = 2013265921`; the extension degree is four. Field
words in the seal and all Poseidon2 digest words are reduced Montgomery
representatives. Conversion to ordinary field values multiplies by
`R^-1 mod p`, where `R = 2^32 mod p`. Digest byte strings use eight little-endian
words. The script rejects words greater than or equal to `p` before hashing.
These boundaries follow the pinned
[BabyBear implementation](https://github.com/risc0/risc0/blob/8c215e2f4ccdd935f0517bf05d90f1ae032840a9/risc0/core/src/field/baby_bear.rs),
[Poseidon2 hash implementation](https://github.com/risc0/risc0/blob/8c215e2f4ccdd935f0517bf05d90f1ae032840a9/risc0/zkp/src/core/hash/poseidon2/mod.rs),
and [IOP reader](https://github.com/risc0/risc0/blob/8c215e2f4ccdd935f0517bf05d90f1ae032840a9/risc0/zkp/src/verify/read_iop.rs).

Three different interpretations must remain distinct:

| Value | Interpretation |
| --- | --- |
| Proof/circuit context bytes | One ordinary field element per byte, via `ProtocolInfo::encode` |
| Outputs, U coefficients, final coefficients, leaves, and digest words | Raw Montgomery words, decoded to field values for the normal-form Python arithmetic |
| `po2` at seal word 32 | Raw integer `18` for sizes; the same raw word contributes ordinary field value `880803832` when hashed with the outputs |

The last row is intentional. Replacing the word with the Montgomery encoding
of the ordinary field value `18` changes the trace-size integer and is rejected.
Treating raw seal words as ordinary field values also fails root reconstruction.
The distinction follows
[`read_slice_with_po2`](https://github.com/risc0/risc0/blob/8c215e2f4ccdd935f0517bf05d90f1ae032840a9/risc0/zkp/src/verify/mod.rs).

U coefficients use four consecutive base words per extension coefficient.
FRI leaves are component-major: component `j` of entry `i` is word `j*16+i`.
The final 64 extension coefficients likewise use a component-major 256-word
encoding. Hashing consumes those actual word orders; no transposition is
introduced. These layouts come from the pinned
[validity verifier](https://github.com/risc0/risc0/blob/8c215e2f4ccdd935f0517bf05d90f1ae032840a9/risc0/zkp/src/verify/mod.rs)
and [FRI verifier](https://github.com/risc0/risc0/blob/8c215e2f4ccdd935f0517bf05d90f1ae032840a9/risc0/zkp/src/verify/fri.rs).

## Actual transcript order

The replay uses the standard `circuit_debug`-disabled native-verifier path.
The context strings are `RISC0_STARK:v1__` and `RECURSION:rev1v1`. Each commit
hashes the specified field sequence or reconstructs the corresponding cap
root, then calls the source-defined RNG mix. Each extension challenge consumes
four consecutive base elements. The order below follows the pinned
[native verifier](https://github.com/risc0/risc0/blob/8c215e2f4ccdd935f0517bf05d90f1ae032840a9/risc0/zkp/src/verify/mod.rs),
[Merkle verifier](https://github.com/risc0/risc0/blob/8c215e2f4ccdd935f0517bf05d90f1ae032840a9/risc0/zkp/src/verify/merkle.rs),
and [FRI verifier](https://github.com/risc0/risc0/blob/8c215e2f4ccdd935f0517bf05d90f1ae032840a9/risc0/zkp/src/verify/fri.rs).

| Zero-based event | Operation | Seal words, half-open range |
| --- | --- | --- |
| 0 | Commit proof-system context | Implicit fixed context |
| 1 | Commit recursion-circuit context | Implicit fixed context |
| 2 | Commit 32 outputs plus raw `po2` | `[0, 33)` |
| 3 | Reconstruct and commit code root; check pinned join ID | Cap `[33, 289)` |
| 4 | Reconstruct and commit data root | Cap `[289, 545)` |
| 5 | Draw 20 base accumulation challenges | No seal words |
| 6 | Reconstruct and commit accumulation root | Cap `[545, 801)` |
| 7 | Draw constraint-mix extension challenge | No seal words |
| 8 | Reconstruct and commit check root | Cap `[801, 1057)` |
| 9 | Draw DEEP extension point | No seal words |
| 10 | Hash and commit 659 extension U coefficients | `[1057, 3693)` |
| 11 | Draw FRI batching extension challenge | AIR validity equation preceding this event is omitted |
| 12 | Reconstruct and commit `fri0` root | Cap `[3693, 3949)` |
| 13 | Draw `fri0` folding extension challenge | No seal words |
| 14 | Reconstruct and commit `fri1` root | Cap `[3949, 4205)` |
| 15 | Draw `fri1` folding extension challenge | No seal words |
| 16 | Reconstruct and commit `fri2` root | Cap `[4205, 4461)` |
| 17 | Draw `fri2` folding extension challenge | No seal words |
| 18 | Hash and commit 64 extension final coefficients | `[4461, 4717)` |
| 19–68 | Fifty query-index draws and their openings | `[4717, 55667)` |

At each query, four base values are **always consumed**. The first nonzero
ordinary field value is selected, or zero if all four are zero, then its low
20 bits select the original index. Openings do not mix the RNG. At a switch
from squeezing to committing, the existing state is permuted first and the
pool cursor resets; the digest is then added into the first eight cells and
the state is permuted again. The JSON report records each commit digest,
each challenge in both ordinary and Montgomery form, the cursor/counters,
and hashes of the entire state before and after every event. The rule follows
the pinned
[`Poseidon2Rng`](https://github.com/risc0/risc0/blob/8c215e2f4ccdd935f0517bf05d90f1ae032840a9/risc0/zkp/src/core/hash/poseidon2/rng.rs).

The replay independently reproduces **44 protocol base samples plus 200 query
base samples**, and **32 RNG permutations**. These are source-level counts for
one native transcript. They exclude commitment hashes, recursive verifier
executions, failed attempts, precomputation and adversarial queries. They are
not `t`, online query mass, a lifetime quantum-query envelope, or a security
estimate.

## Cap and opening reconstruction

Each of the seven trees has 32 ordered cap digests. Reconstructing the caps
uses 31 pair hashes per tree, 217 in total. Each query opens accum, code, data,
check, `fri0`, `fri1`, and `fri2` in that order. The opening checker hashes the
actual leaf width, consumes sibling digests from leaf toward cap, uses the
low bit of `index + rows` to choose left/right order, and compares the result
with the selected cap slot. The JSON includes every sibling and computed
parent digest, virtual node index, cap index, and exact input word range.
This is the algorithm in the pinned
[Merkle verifier](https://github.com/risc0/risc0/blob/8c215e2f4ccdd935f0517bf05d90f1ae032840a9/risc0/zkp/src/verify/merkle.rs).

| Tree | Rows | Leaf base words | Siblings per opening | Openings | Distinct opened indices |
| --- | ---: | ---: | ---: | ---: | ---: |
| accum | 1,048,576 | 12 | 15 | 50 | 50 |
| code | 1,048,576 | 23 | 15 | 50 | 50 |
| data | 1,048,576 | 128 | 15 | 50 | 50 |
| check | 1,048,576 | 16 | 15 | 50 | 50 |
| fri0 | 65,536 | 64 | 11 | 50 | 50 |
| fri1 | 4,096 | 64 | 7 | 50 | 49 |
| fri2 | 256 | 64 | 3 | 50 | 44 |

The replayed roots, encoded as little-endian Montgomery digest bytes, are:

| Tree | Root |
| --- | --- |
| accum | `d9ade72aae7e532bfb617b02dc68f465b80d4705db22c9767b25f0181f400c59` |
| code | `7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e` |
| data | `f9567419c290aa30b08c13445b0be1620aaea32095e0e01ba9e2202957f3003f` |
| check | `074c912a62c01b053f048662b87d7f534139b7516a780059550bf52eec814e0c` |
| fri0 | `f19eff1daeda5b2d19774d22b81e9858a121ba00a7ec9b4550332a5f140e2c07` |
| fri1 | `0c51412dcc5caa6de3719c606e4cae357c160e15480ad32f95b2a50969e6dc4a` |
| fri2 | `ac5fec30883dff515c195e3082820c000e0ce207c457c21fa5e937151789063b` |

Only the code root is compared with an externally fixed control ID by this
replay. The other roots are reconstructed from their caps, committed in their
actual transcript positions, and checked against their openings. Reproducing
these computations does not independently authenticate the non-code roots or
prove a quantum binding/extraction theorem for this construction.

## The fifty actual indices and their projections

The original indices, in query order, are:

```text
 0– 9: 777360, 1029483, 926527, 135095, 659855, 653999, 346658, 68588, 627804, 381604
10–19: 854335, 521051, 954209, 874654, 370172, 218097, 959569, 810775, 49212, 954311
20–29: 612988, 869978, 487393, 628921, 98259, 13084, 907605, 476335, 334909, 382597
30–39: 633017, 954646, 439418, 774244, 1019200, 487422, 19778, 713896, 665368, 184696
40–49: 291096, 1025548, 193710, 38217, 800468, 520982, 841901, 376474, 475464, 209180
```

At each radix-16 round the source computes `quotient = pos // round.domain`,
`group = pos % round.domain`, opens leaf `group`, and replaces `pos` with `group`.
The report preserves both quotient and group, including component offsets
`j*16+quotient`; the projections are correlated, not new independent samples.
The final evaluation index is the original index modulo 256. This mapping is
in the pinned
[`verify_query`](https://github.com/risc0/risc0/blob/8c215e2f4ccdd935f0517bf05d90f1ae032840a9/risc0/zkp/src/verify/fri.rs).

| Layer | Repeated index | Query numbers, zero-based |
| --- | ---: | --- |
| fri1 | 2233 | 23, 30 |
| fri2 | 22 | 31, 45 |
| fri2 | 24 | 38, 40 |
| fri2 | 28 | 25, 49 |
| fri2 | 63 | 2, 10 |
| fri2 | 175 | 5, 27 |
| fri2 | 185 | 23, 30 |

The tests compare the actual repeated leaf-plus-path bytes and find them equal
for each pair. Nevertheless, **same leaf does not imply the same selected
component**. For example, queries 31 and 45 both open `fri2` leaf 22, but their
quotients are 1 and 3. Queries 23 and 30 both open `fri1` leaf 2233 with quotients
9 and 10. The omitted algebraic goal checks would use those different entries.
The replay validates the shared commitment paths and records the selection;
it does not evaluate those goal checks.

There are still **50 sampled query paths**. Neither 49 nor 44 is substituted
for a theorem's query parameter. A single deterministic receipt does not
establish a sampling distribution, entropy, independence assumption, extraction
cost, RBR error, or quantum security bound. Repeated indices are an actual
commitment/recursive-verifier interface obligation, not an attack discovered
by this replay.

## Independent arithmetic checks and mutation controls

At startup, the replay extracts three expected vectors directly from the
SHA-256-pinned upstream Poseidon2 source: the 24-element permutation vector,
the aligned 32-element sponge vector, and the unaligned 17-element vector.
The upstream source describes the two sponge vectors as coming from an
independent interpreter. The replay does not manufacture expected values
from its own output. See the pinned
[upstream tests](https://github.com/risc0/risc0/blob/8c215e2f4ccdd935f0517bf05d90f1ae032840a9/risc0/zkp/src/core/hash/poseidon2/mod.rs).

The new differential test then uses a separate arithmetic path: raw Montgomery
state, explicit full external/internal matrices, and the pinned matrix/round
constant arrays. It does not invoke the optimized helper's permutation,
sponge, conversion functions, or RNG methods. It checks the before/after state
of all 69 actual events and all 244 ordinary-field samples, including rate
exhaustion and switching back from squeezing to committing. Commit digests
are the replay's recorded inputs to this differential RNG; this test is not a
second independent proof of all message hashes or formal equivalence for every
possible input.

The 13 tests also exercise concrete failure boundaries:

- Canonical changes to outputs, U coefficients, final coefficients, or any of
  the seven caps must fail an actual code-root or opening check, before the
  final receipt identity check.
- A leaf or sibling mutation in each oracle, the last sibling in query 49,
  reordered siblings, and a wrong query index must fail the appropriate opening.
- Treating Montgomery words as ordinary values, swapping the context order,
  or skipping the squeeze-to-absorb permutation must fail replay.
- Zero fallback samples still consume all four values. Noncanonical field
  words, wrong variant byte order, truncation, surplus bytes, and a changed
  declared seal length are rejected.
- A changed outer suffix fails the final whole-receipt identity check. Changed
  upstream source, snapshot bytes or local helper bytes cannot silently repin
  the result. A changed permutation constant fails the upstream golden check.

These are fault-injection and implementation checks. They do not show that an
attacker produced an accepted malformed receipt, and they do not close any
quantum extraction or state-restoration obligation. There was no failing
implementation run in the initial recorded replay or the initial 13-test run;
expected negative-control exceptions are distinct from accepted attacks.

## Reproduce and interpret the report

From the repository root, with the exact historical fixture and source snapshot
available:

```sh
bash scripts/project-preflight.sh
python3 scripts/ci/test_w1_fri_query_replay.py -v
python3 scripts/w1_fri_query_replay.py --output /tmp/w1-fri-query-replay.json
```

The output schema is `TRNM-W1-FRI-QUERY-REPLAY1`. `--output` creates a new file
and refuses to overwrite existing evidence. Without it, the script emits JSON
to standard output. An unsupported input or failed check yields a nonzero exit
and no successful report. The JSON includes generator/helper/source identities,
the complete transcript, every cap level, every opening path, all query indices,
folding positions, repeated-index groups and the explicit false qualification
fields.

This artifact strengthens the **actual encoding**, **commitment-path**, and
**Fiat–Shamir transcript mapping** portions of the eight-interface checklist.
It does not establish the semantics of Node/guest/VM/AIR, RBR knowledge
extraction, quantum state restoration, a joint ideal-oracle model, repeated-index
quantum multi-extractability, composition for all allowed recursion programs,
or the lifetime error budget. Those claims require the missing theorems and
implementation mappings recorded in the
[implementation map](W1_QROM_IMPLEMENTATION_MAP_20261107.md), not extrapolation
from this successful fixed-fixture replay.
