# Reversible arithmetic and SHA-256 component observation

This is a research component of the existing pure-PoN work package, not a new
consensus profile or a complete quantum winner oracle. The sole development
plan remains [the project plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
The authoritative relation remains the [pure-PoN work and security model](../../docs/protocol/pon-nakamoto-v1/details/PURE_PON_WORK_SECURITY_MODEL_V1.md)
and the original [native W1 implementation](../../trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs).

## Constructed object and execution boundary

`reversible_components.py` builds explicit X, controlled-X and Toffoli gate
lists for multiplication modulo `2^32 - 5` and the complete 64-round SHA-256
compression function. Both operands of multiplication are input registers.
The hash component has a 512-bit message input and a 256-bit chaining-state
input; neither is replaced with a measured test value during construction.
Only structural Boolean constants are folded.

Each component implements the reversible map
`(input, zero scratch, output) -> (input, zero scratch, output XOR f(input))`.
The implementation retains its computation, copies the result into a distinct
output register, and appends every inverse gate explicitly in reverse order.
The input registers must be unchanged and every scratch bit must be zero
after each observed execution. The intentionally simple construction retains
many intermediate values. Its space requirements are not an optimality claim.

The exported `TRNM-QIR1` artifact contains a canonical JSON register description
and actual packed gates. A separate strict decoder reopens the artifact and
checks types, lengths, bounds, disjoint registers, gate arity, unused encoding
bits and wire aliases. The reopened artifact is the one actually executed by
the classical basis-state checker. Re-encoding and all gate metrics must match.
This format grants no transaction, block, model-installation or protocol authority.

The tests include all 256 input pairs for four-bit addition and all 256 pairs
for multiplication modulo 11, nonzero output targets, malformed encodings,
and a deleted inverse gate that must be detected through dirty scratch.
The 32-bit observation includes all 49 pairs of seven boundary values and
64 reproducibly sampled pairs. Canonical and noncanonical field inputs are
included. Supporting noncanonical inputs in this arithmetic component does
not remove W1's separate canonical-encoding rejection.

The SHA observation checks seven complete padded messages against Python's
independent `hashlib.sha256`, covering empty input, `abc`, both sides of the
55/56-byte padding boundary, 64 and 65 bytes, and a 256-byte message. Each
compression invocation checks unchanged inputs and clean scratch. Connecting
these invocations with classical chaining variables is not a coherent
multi-block quantum circuit and is not reported as one.

## Measurement interpretation

The raw observation records each input, expected result, actual result, exported
netlist digest and size, constructed gate counts, logical input/output/scratch
qubits and dependency depth. Depth assumes all-to-all connectivity. The
Toffoli-only dependency depth ignores Clifford cost while still propagating
dependencies through those gates.

The optional T count is only the conditional arithmetic conversion of seven
T gates per exact Toffoli. This package does not transpile that decomposition,
schedule a fault-tolerant machine, supply magic-state factories or estimate
physical qubits or seconds. Classical construction and basis-check wall times
are labelled as classical measurements. They are not quantum execution times,
Grover runtimes, mining energy estimates or measured speedups.

The component netlists describe constructive upper costs for these specific
functions in the stated gate model. They establish neither a lower bound on
the best attacker nor an upper cost for the complete W1 oracle. In particular,
an attacker may specialize public constants, use a better arithmetic circuit,
trade space against depth and legally preprocess each public task.

## Missing complete W1 oracle

The original relation has four noise-factor expansions. Each expansion samples
512 field words from domain-separated SHA-256 outputs and rejects after at
most 128 hash invocations. With the current native framing, a single noise
hash has 66 input bytes and two SHA-256 compression blocks. Thus evaluating
all four maximum-length streams would include 1,024 compression invocations.
This is a byte-and-loop count, not a measured reversible rejection sampler:
the coherent selection, retained rejection flags, bounded failure case and
uncomputation are still missing.

The original transcript hashes the 16-byte `TRNM-PON-TRACE1` domain including
its final zero byte, the 32-byte challenge, and 32,768 updated prefix words of
four bytes each. Its 131,120-byte input takes 2,049 padded SHA-256 compression
blocks. The 32,768 words are the actual ordered intermediate matrix values,
not independent hash puzzles. Multiplying the measured component counts by
this number does not construct the matrix computation, its coherent memory
schedule, a phase oracle or the outer inverse.

A complete resource result must still implement and verify:

- The selected search-space freedoms, challenge and header bindings, field
  canonicality, task eligibility and target comparison.
- All four bounded noise expansions, their coherent accepted-word selection
  and the original failure behavior.
- The full low-rank factors, matrix arithmetic and exact tiled-prefix order,
  including a reversible memory and garbage-cleanup schedule.
- The trace and ticket domains, phase marking and uncomputation of the whole
  predicate, with no omitted relation or extra ticket from proof randomness.
- Legal public-task preprocessing, including precomputable `C = A B`, and
  comparison with the best legal classical and quantum strategies.
- A specified error-corrected hardware model and separate quantum soundness
  analysis of any proof system used by validators.

The existing DAA/ASERT and fixed-probability variable-work experiments remain
conditional models. These component observations do not convert their rate
parameters into a demonstrated quantum miner. They do not change chain
weighting, deploy a new work profile or create a classic-work fallback.

## Reproduction

Run the project preflight, then use a fresh output directory outside the source
tree so exact committed-source verification is not made dirty by measurements:

```sh
bash scripts/project-preflight.sh
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p test_reversible_components.py -v
python3 formal/pon-nakamoto-v1/reversible_components.py --output /tmp/pon-reversible-new-observation
```

Retain the full report and both netlists, the source commit and raw-byte source
verification before and after execution, native relation hash, commands,
exit statuses and failures. Earlier observations from earlier source versions
must remain separate. Passing this component experiment is not completion of
work package 2C or whole-chain post-quantum acceptance.

The fault-tolerant accounting distinction is consistent with Amy et al.,
[Estimating the cost of generic quantum pre-image attacks on SHA-2 and SHA-3](https://arxiv.org/abs/1603.09383).
That paper's physical costs are not imported as estimates for this W1 relation.
