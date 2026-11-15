# Public SHA schedule backend — research profile 5

Qualification: **HOLD_NO_GO**. This increment changes the SHA AIR representation,
not the W1 hash, native relation, PCS parameters or production profile. It does
not establish complete noninteractive security, PQ128, a global rejection bound,
a universal physical work lower bound, or production Node qualification.

## Exact reduction

The original complete public W1 statement and independent expected header and
artifact identifiers are decoded by the unchanged `public.rs` and `sha_plan.rs`.
They determine all 519 messages, 4,114 real SHA-256 compressions, their standard
padding and their order. In particular, all 128 counters for each of the four
noise labels remain present, including unused noise tails.

For each canonical padded block, the verifier interprets its sixteen words as
big-endian u32 integers and computes the standard SHA-256 message schedule:

`W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16] mod 2^32`.

Each of the 64 words is fixed as two u16 limbs in the verifier's independently
constructed preprocessed matrix. The schedule and its verifier key are never
accepted from proof bytes, a prover cache, or an untrusted sidecar. The public
constructor does not execute SHA-256 compression, evaluate a digest, or certify
any claimed output. Its schedule arithmetic and the larger preprocessed matrix
are paid in every fresh verifier process.

The new witness retains the official input-state limbs, both 68-word bit chains,
all 64 rounds' packed intermediates and all eight final-state bit words. All
compression constraints are retained, including Boolean checks, sigma/Ch/Maj,
addition carry constraints, IV selection, cross-block links and final digest
comparison. Only the public schedule's witness bits and auxiliary columns are
removed. The padding rows still encode valid zero-block compressions with the
fixed SHA-256 IV and cannot feed real messages.

| Fixed property | Original SHA, component 1 | Public schedule SHA, component 5 |
| --- | ---: | ---: |
| Wire magic | `W1P3SHA1` | `W1P3SCS4` |
| Height | 8,192 | 8,192 |
| Main width | 7,728 | 5,392 |
| Preprocessed width | 27 | 139 |
| Main next-row column dependency | first 16 | first 16 |
| Preprocessed next-row dependency | none | none |
| Maximum constraint degree | 3 | 3 |
| Quotient chunks | 2 | 2 |
| FRI queries / log blowup | 64 / 2 | 64 / 2 |
| Scheduled SHA envelope upper bound | n/a | 3,338,565 bytes |

The 2,336 removed main columns are 64 × 32 schedule bits and 48 × 6 schedule
auxiliaries. The additional 112 preprocessing columns result from replacing
16 public block words by 64 × 2 schedule limbs. Main plus public width falls
by 2,224 columns. This is a shape calculation, not a timing result.

## Relation argument and its limits

Take any trace satisfying the new AIR under its independently derived public
preprocessing. Extend each row by inserting the canonical bits of the 64
schedule words and the corresponding canonical small-sigma/partial-sum
intermediates. The removed official schedule constraints and message-word
packing constraints hold by this deterministic construction. Every retained
constraint is the same official compression constraint, with its schedule
operand replaced by the equal two-limb public value. The original wrapper's
IV, chaining and output conditions are unchanged. Thus the extension is a
satisfying witness for the original complete-message AIR. Honest complete SHA
executions project to the new layout, which is tested against the official
trace generator column for column.

This is a relation-level extension argument. It is not an independently
established soundness theorem for the official compression AIR, PCS, hash,
Fiat–Shamir transform or their composition. The actual Goldilocks/Poseidon2
hash-construction limitations and conditional estimator assumptions inherited
from profile 1 remain open. Profile 5 has a fresh component domain and wire
magic; no query count, blowup or grinding parameter is weakened.

The arithmetic proof remains packed carry component 4, preserving all 81,920
original relation rows and the separately reviewed limb/carry equations. The
public statement remains exactly 377,290 bytes. No native acceptance or host
computed digest replaces either proof verification.

## Code provenance

`sha_schedule_air.rs` adapts the compression constraints and trace generator
from the installed, Cargo.lock-pinned `p3-sha256-air` 0.8.0 package, licensed
`MIT OR Apache-2.0` by its Cargo metadata. Its upstream repository is
<https://github.com/Plonky3/Plonky3>. This adaptation retains the original
remaining column order and formulas. The message-schedule constructor and
wrapper are specific to this public W1 research profile.

| Upstream file | SHA-256 |
| --- | --- |
| `src/air.rs` | `42a079d9cc36a10162e42c73f6b816bb97ae67aa7f998be2a89f789d1882f88d` |
| `src/generation.rs` | `b9bd18aa6325b39bf2b60511069f6373b5629f25f497c23da6adbdf3d7981c6f` |
| `src/columns.rs` | `1b9f9b24b420958497a5acf868fa7ab93df4de4996ab353f40dc9a0489f0ffbc` |

## Execution and malformed input boundaries

`scheduled_sha_backend` uses the same bounded statement reader and independently
expected inputs as the prior runner. Both SHA and arithmetic buffers must pass
the fixed-shape, allocation-free scanner before either bincode decoder runs.
Component 5's exact fixed shape has minimum 3,033,413 bytes, maximum 3,338,565
bytes, 1,338 vector headers and at most 9,536 Merkle siblings. The limit covers
syntax only; the unchanged PCS verifier still checks authenticated paths and
algebra. It is not a total wall-time or process-memory bound.

The runner always returns `HOLD_NO_GO`, including on a valid complete W1 proof.
Historical components 1–4 and their envelope bounds remain supported. The
production `PGH2` growth profile is outside the original `PNH1` W1 statement
implemented here.

## Validation and measurement scope

The source has focused tests for honest single/multiblock execution, exact
projection of every remaining official trace column, public-only preprocessing,
wrong IV, broken cross-block link, wrong padding, changed public message/digest,
changed schedule limb and Boolean/first/final round mutations. A genuine
four-row PCS proof tests independent public verifier-key reconstruction and
rejection of altered public data, verifier keys, transcript domains, openings,
commitments and degrees. These small proofs are not full W1 performance samples.

`run_schedule_abba.py` runs complete fresh prepare/prove/verify process chains
for the retained and dense fixtures, with one ABBA sequence per input. It pins
source, binaries, inputs, independent expectations, native build settings and
resource configuration, records each process's full logs and resource usage,
and checks the source/binary/input identities again at completion. The host is
shared and the benchmark records observed load and cgroup pressure. Results
must be read from the retained campaign, not inferred from column counts.

Raw and prefix fixtures are preconstructed inputs to this research pipeline.
Mining, prefix discovery/generation, production transport, production Node
admission and lifecycle costs are not included. The 49,506-byte native candidate
and native verification remain the relevant separate reference: even the
377,290-byte public statement alone is larger. A positive result relative to
the prior STARK is not a positive production or native end-to-end result.

All failed builds, test failures and measured regressions are retained; no
historical R3 sample or failed carry candidate is overwritten.
