# Complete W1 public AIR/STARK research

Qualification: **HOLD_NO_GO**. This crate is an isolated research backend. It
does not activate a node, change consensus, grant production eligibility, or
provide a concrete noninteractive or quantum security theorem.

The measured result, exact proof identities, same-host comparison and open
gates are in [ROUND_REPORT.md](ROUND_REPORT.md). The raw numerical derivation
is in [MEASUREMENTS.json](MEASUREMENTS.json).

## The statement actually proved

The verifier consumes the original 49,506-byte W1 candidate, the complete
131,072-byte prefix in its original `bi,bj,bk,i,j` byte order, public hash
claims, and public arithmetic intermediates. These form a bounded
**377,290-byte** research statement (`W1P3PUB1`). Expected header (318 bytes)
and A/B artifact commitments (64 bytes) are supplied independently. They
are not taken from an untrusted candidate or proof envelope.

The conjunction of two proofs covers:

1. **Complete SHA messages.** Artifact A, qualified task input B, task,
   challenge, all 4 × 128 original noise-counter messages, the complete
   prefix trace hash, ticket, and work ID: 519 messages and 4,114 compression
   operations. SHA padding, original framing, IV, consecutive block states,
   and final digests are constrained, using the official Plonky3 0.8.0
   SHA-256 compression AIR plus this crate's wrapper. The trace is padded
   to 8,192 rows with 7,728 main columns and 27 public preprocessing columns.
2. **Complete arithmetic.** All E/F factor products, all Ahat/Bhat additions,
   all eight full noisy prefix relations, and full `AB=C`: 81,920 real rows,
   padded to 131,072 rows, with 516 main columns and 18 public preprocessing
   columns. Every eight-term dot product reduces individual products before
   adding, so the Goldilocks proof field cannot alias a whole-dot overflow.
   Canonical public values are in `q = 2^32 - 5`. The original accepted-noise
   selection and the original 128-digest-per-label exhaustion rule are retained.

`PublicStatement::plans` deterministically constructs both AIR inputs from
the same encoding and independent expectations. It does not evaluate native
matrix products or native W1 SHA digests to accept a result. Hash claims are
proved by SHA AIR; arithmetic claims are proved by the arithmetic AIR. The
verifier rebuilds each preprocessing commitment and verification key itself.
It accepts no proof-supplied key, arbitrary arithmetic row list, or arbitrary
SHA plan as a complete W1 statement.

The extra public intermediates make this construction non-succinct in its
public statement and non-zero-knowledge. A successful execution is evidence
that the complete relation ran through actual PCS/FRI proof machinery, not
evidence of end-to-end speedup.

## Fixed proof profile

All P3 crates are pinned to **0.8.0** with a Cargo lockfile. The proof field
is Goldilocks; challenges use its quadratic extension `X^2 - 7`. MMCS and
challenger use the upstream default Goldilocks Poseidon2 width-8 permutation,
with separate fixed application domains for SHA and arithmetic. Native W1
messages continue to use the constrained SHA-256 relation.

| Parameter | Fixed value |
|---|---:|
| FRI log blowup | 2 |
| FRI queries | 64 |
| Final polynomial log length | 0 |
| Maximum log folding arity | 1 |
| Batch / commit / query / OOD / lookup grinding | 0 |
| MMCS arity / digest elements / cap height | 2 / 4 / 0 |
| Maximum envelope bytes, each component | 67,108,864 |

The binary envelope uses separate `W1P3SHA1` and `W1P3ARI1` magics followed by
bincode 1.3 fixed-integer encoding. Deserialization has byte limits and
rejects trailing data. Trace degrees are fixed to 13 and 17 before verifier
setup. Verification panics are contained and reported as rejection. These
measures do not establish a global time or memory bound against every
malformed proof.

`security_metadata` inspects actual constraints and opening shapes using
`StarkSecurityParams::from_air`. Preprocessing widths and batching are
included: 15,487 batching functions for SHA and 536 for arithmetic. Its
127-bit field-size lower bound is conservative for the quadratic extension;
its assumed 128-bit hash collision strength is an explicit assumption.
The resulting round-by-round estimates are not an instantiated Fiat–Shamir
forgery bound. Concrete transcript sampling, PCS/hash binding, lifetime
oracle budgets, ROM compilation, and QROM analysis remain separate gates.
PaddingFreeSponge's use here is restricted to the fixed typed MMCS shapes;
this document does not certify a general variable-length hash construction.

## Reproduction

Use the checked-in lockfile and Rust 1.95.0 or a compatible pinned toolchain.
Keep every attempt in a new results directory. The runner uses create-only
outputs to preserve failed observations and prevent mixing proof versions.

```bash
export RUSTFLAGS='-C target-cpu=native'
export RAYON_NUM_THREADS=8
cargo +1.95.0 test --release --locked --offline --all-targets --jobs 2
cargo +1.95.0 build --release --locked --offline --jobs 2
cargo +1.95.0 build --release --locked --offline --examples --jobs 2
python3 -B run_campaign.py prove fixtures/retained results/retained-run-01
python3 -B run_campaign.py verify results/retained-run-01
python3 -B run_late_controls.py results/retained-run-01
```

Offline builds require the lockfile's crates already present. Missing
dependencies are an explicit build failure. The four retained fixture files
are byte-for-byte copies from the prior independently checked W1 evidence
bundle; each run records their full SHA-256 and the exact source/binary hashes.
`target-cpu=native` enables the current host's instruction set; rebuild on a
different host and retain that host's features rather than moving the binary
and calling the observations equivalent. Both sides of a native comparison
must use the same declared toolchain and optimization policy.

To verify the retained final proof pair on another machine, use the direct
verifier command with that machine's rebuilt binary and the checked-in
independent expectations:

```bash
target/release/w1-full-public-stark-research verify \
  results/retained-native-02/statement.bin \
  fixtures/retained.expected-header.bin fixtures/retained.artifacts.bin \
  results/retained-native-02
```

The campaign scripts deliberately require the original binary fingerprint
when replaying a measured run. A direct cryptographic replay with a rebuilt
binary is a new observation and does not inherit the recorded clocks.

The `prepare` command computes the extra public witness and is timed as
prover work. It does not claim that the statement has been proved. `prove`
constructs the two traces sequentially, performs actual proving, and saves
both proof byte strings. It also reports preparation, preprocessing, trace
generation, proving, and persistence separately. `verify` independently
reads bounded files, reconstructs both canonical AIRs and keys, and only
reports `VERIFIED_COMPLETE_W1_RESEARCH_ONLY` after both STARK checks succeed.
Diagnostic SHA-256 fingerprints of files are included in total process time;
they do not replace proof verification of the W1 hash relation.
Preparation consumes an already constructed complete prefix. The retained
native baseline separately records its reconstruction from the existing raw
candidate; the report accounts for that boundary. These commands do not mine
a nonce, generate the original candidate from a task, or measure network and
production scheduling.

The campaign runs three fresh successful verifier processes and eleven
negative controls, including a last-C change that leaves the SHA relation
unchanged and reaches arithmetic verification. It retains combined process
logs, exact exit codes, outer process wall time, and `/usr/bin/time -v`
resource observations. The largest sampled rejection time is not the
adversarial maximum. Native comparison must be measured on the same host
and reported with its thread count, scope, and prefix construction cost.

`run_late_controls.py` adds four typed controls. It preserves every
proof-carried transcript field while changing either the last query's final
fold value or one digest element in the last nonempty shared commit-phase
authentication proof. The exact expected errors are `FinalPolyMismatch` and
`CommitPhaseMmcsError(CapMismatch)`. Shared multiproofs are not independent
per-query Merkle paths. The second control reaches authentication after all
64 query fold chains and final-polynomial checks; it still does not identify
the global latest rejection over every possible malformed input.

The first late-control script expected the wrong upstream error name
`RootMismatch`. Its failed assertion, the actual rejection, and the original
script bytes are retained with the run-01 evidence. The corrected script
requires the precise observed variant instead of accepting arbitrary errors.

## Boundaries still open

The complete concrete noninteractive proof, production resource limits,
worst-case rejection cost, economic gain, cheapest-strategy physical work
bound, and production integration remain gates until supported by their
own evidence. Neither successful test counts nor this research verdict
change **HOLD_NO_GO**.

## 2026-11-08 fixed-profile wire admission

The continuation adds [allocation-free structural admission](WIRE_ADMISSION.md)
before decoding or verifier setup, with exact per-component envelope bounds,
13 native mutation tests, a 96-process malformed-shape comparison, and
an explicit successor replay of the 11 ordinary and four late controls.
The original proof/security results above remain historical. This is not
a global resource, noninteractive-security, physical-work or Node qualification.
