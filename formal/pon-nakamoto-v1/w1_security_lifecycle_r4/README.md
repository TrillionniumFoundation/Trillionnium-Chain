# W1 R4 restricted-leaf theorem and native lifecycle accounting

Status: **HOLD_NO_GO**. Actual W1 noninteractive, lifetime-failure and quantum
security fields remain `null`; `pq128` remains `false`. This successor leaves
the historical R3 audit and production configuration unchanged.

This directory delivers a proved classical ideal-permutation lemma for one
actual FRI leaf domain, transparent instrumentation of the real P3 verifier,
and an executable source-pinned lifecycle accountant. It does not supply the
missing Merkle/vector extraction theorem, a complete PCS/IOP/Fiat–Shamir
composition, or a concrete-security reduction for Poseidon2.

## Scope and source identity

Two historical sources are deliberately distinguished:

| Observation | Repository source | Components |
| --- | --- | --- |
| R3 retained proof measurements | `cc836dfc13ef0006eb0878abd8cb5eca9a76bec0` | Original SHA1 and packed4 |
| R4 retained-B measurements | `eb944645cc3e30af5955edf9dbbcb43488fa38c1` | Public-schedule SHA5 and packed4 |

All use the retained Cargo.lock, SHA-256
`35e29723f30ca10dd6712403456755ac41cb8d73d963ab73f8cbd7a8d69d3ae1`,
and P3 0.8.0. The scalar field is Goldilocks, the challenge extension has degree
two, the FRI query count is 64, blowup is four, final polynomial length is one,
folding is binary, and all four kinds of PoW difficulty are zero. The leaf
sponge, branch compressor and duplex transcript clone the same fixed
Poseidon2Goldilocks width-eight permutation. Component tags do not create new
independent permutations.

[source_contract.json](source_contract.json) pins 57 repository/registry/probe files,
all four native receipts and both successful probe source versions. Its exact
bytes are sealed by a SHA-256 constant in the checker. The checker reads the two
named **git objects**, installed registry bytes and the current probe bytes: this supports historical
attribution, and does not certify arbitrary working-tree edits or latest main.
The seal is a reproducibility guard, not a signature or a proof that observations
were honestly produced.

## Proved increment

Binary FRI rows contain two quadratic-extension elements, which `ExtensionMmcs`
flattens to four base-field elements. The actual one-block leaf is
`H4(m) = first4(Pi(m || 0^4))`. Let `N = p^4`. In the classical ideal-permutation
game, allow an adaptive adversary both forward and inverse access. Charge all
shared-role, honest, offline and cross-version queries to `Q`; put `T = Q + 2`
for the final checks of two different returned messages. The proved bound is

\[
\Pr[H_4(m_0)=H_4(m_1),\ m_0\ne m_1]
\le \min\!\left(1,\frac{N T(T-1)}{2(N^2-T+1)}\right)
\quad(T\le N^2),
\]

with the trivial bound one when `T > N²`. The proof exposes a permutation table
adaptively and counts a bad event only when the second **restricted-domain**
input acquires an already exposed restricted output prefix. It handles inverse
queries explicitly. It does not assume independent events. See
[THEOREM.md](THEOREM.md) for the proof, exact zero-query check and saturation.

R3's arbitrary-input compressor collision does not establish an attack in this
restricted game. Conversely, this lemma cannot be applied to unrestricted
branches, other leaf widths, Merkle openings, vector extraction, the full W1
proof, quantum queries or the concrete published Poseidon2 algorithm. Those
distinctions are enforced in every generated result.

## What the native probe actually measured

`lifecycle_probe.rs` is also installed as the research example
`w1_public_stark_research/examples/r4_lifecycle_probe.rs`. It wraps the existing
permutation without changing its input or output, and uses the actual challenger
for all samples. It verifies with the original configuration first, checks that
instrumentation preserves proof serialization and the independently reconstructed
preprocessing commitment, verifies again, then repeats to compare actual sampled
challenge values, indices and evaluation counts.

Counters include every scalar-equivalent SIMD lane and repeated input. They
measure Poseidon2 evaluations, not unique oracle points, all hash calls or CPU
operations. P3's Keccak-based typed-pattern/algebra identity mechanism is outside
these counters. Native verification used one Rayon thread. These runs were
diagnostic verification of retained complete proofs, not a new proof-generation
or performance campaign.

| Exact retained observation | Init | Independent preprocessing | One verification | Cold total |
| --- | ---: | ---: | ---: | ---: |
| R3 SHA1, 4,356,101 proof bytes | 12 | 262,143 | 136,754 | 398,909 |
| R3 packed4, 453,861 proof bytes | 12 | 3,014,655 | 14,971 | 3,029,638 |
| R4 SHA5, 3,146,949 proof bytes | 12 | 1,179,647 | 98,990 | 1,278,649 |
| R4 packed4, 453,861 proof bytes | 12 | 3,014,655 | 14,971 | 3,029,638 |

The measured R3 pair has 151,725 verification calls and 3,428,547 cold total
evaluations. The R4 pair has 113,961 and 4,308,287 respectively. The public
schedule reduces the counted verification phase while increasing independently
rebuilt preprocessing. These numbers alone do not determine runtime or an
end-to-end backend result.

For SHA5, one verification splits into 89,160 leaf evaluations, 4,308 branch
evaluations and 5,522 transcript evaluations. Its initialized transcript replay
has 5,534 evaluations. The initialized SHA1 and packed4 transcript replays have
7,814 and 347 respectively. The separate Python buffer machine reproduces the
native counts from absorb/squeeze lengths, including full-block reuse and
discarded outputs. SHA1/SHA5 each sample 96 base-field values, packed4 samples
98; each includes precisely 64 index samples.

The receipts concern the exact retained statements/proofs. They are not maxima
over arbitrary accepted or malformed proofs. Diagnostic baseline verification,
negative controls, proof generation, other sessions and offline adversarial work
must not be silently inferred from these per-phase counters.

## Falsified hypothesis retained

The initial conjecture that zero difficulty permits arbitrary PoW witnesses was
false. P3 0.8.0 checks canonical zero witnesses before the skipped grinding
steps. On each of all four retained observations, separately changing OOD,
batching, first commit, last commit or query witness from zero to one passed the
structural scanner but was rejected by the native verifier without a panic.
The exact errors, byte offsets and mutated-proof SHA-256 values remain in each
receipt. There is no demonstrated proof-deduplication bypass or false-statement
forgery here. [FAILURES.md](FAILURES.md) preserves this and the failed first
native build instead of replacing them with a success-only record.

## Lifecycle executable

Run from this directory after the two source commits and locked registry source
are available:

```bash
python3 -m unittest -v test_lifecycle_budget.py
python3 lifecycle_budget.py \
  --source-manifest source_contract.json \
  --repo-root /path/to/Trillionnium-Chain \
  --registry-root /path/to/cargo/registry/src/index.crates.io-1949cf8c6b5b557f \
  --receipt artifacts/sha-v1/receipt.json \
  --receipt artifacts/packed-v1/receipt.json \
  --receipt artifacts/scheduled-v1/receipt.json \
  --receipt artifacts/packed-r4-v1/receipt.json \
  --scenarios scenarios.json
```

The eleven supplied cases exercise cold initialization, one million repeated
verifications with reused preprocessing, a shared permutation across old and
new component domains, explicit offline forward/inverse query budgets, long
lifetimes and saturation. The first cases are verifier-workload arithmetic;
zero entries for unmeasured work are explicit hypothetical omissions, not proof
that such work cannot occur. Other cases provide hypothetical allowances. None
establishes a complete experiment's query upper bound. The exact scalar counts
are useful inputs to a future complete theorem, and are not that theorem.

The accountant sums every role and epoch **before** applying a quadratic term.
It displays the cross terms that a separate-role calculation would omit, without
asserting a birthday theorem for the already-falsified unrestricted compressor.
It requires explicit offline forward, inverse and other-honest counts. Receipt
keys retain both the source and component attribution, so old and new packed4
observations can coexist without overwriting each other.

The independently labelled conditional-hazard calculation proves only the usual
adaptive union lemma under its stated per-history hazards. No independence is
required. The checker never substitutes proof counts for offline queries, never
maps the 63.95384529640614-bit conditional RBR estimator to those hazards, and
offers no input flag capable of producing an actual NI/PQ security conclusion.
Exact rational arithmetic drives decisions; floating-point logarithms are for
display only.

## Remaining cryptographic work

The first security gate still requires the complete fixed P3 AIR/PCS/IOP relation
and concrete RBR reduction, restricted MMCS binding and extraction under the
shared permutation, the exact length-tagged duplex/compiler mapping in the same
oracle game, concrete Poseidon2 instantiation, and quantum extraction/compiler
constants. The latest primary literature narrows the relevant interfaces but
does not supply those mappings automatically; see
[PRIMARY_SOURCES.md](PRIMARY_SOURCES.md).

The independent static review of the new public-schedule relation is recorded in
[SHA_SCHEDULE_INDEPENDENT_REVIEW.md](SHA_SCHEDULE_INDEPENDENT_REVIEW.md). It does
not close any of these cryptographic requirements. Production Node qualification,
global malicious-rejection cost and the cheapest legal strategy's physical-work
lower bound are outside this successor's claims.

## Validation retained with this successor

- 24 Python tests passed, including four actual receipt replays and exhaustive
  short duplex-buffer sequences against an independent literal simulator.
- The real repository/registry check matched all 57 pinned files and evaluated
  all eleven lifecycle cases; every actual W1 NI/PQ field remained null/false.
- CLI controls for a changed manifest, changed native receipt, omitted offline
  inverse budget and missing registry source each returned refusal exit 2.
- All four native observations passed original and instrumented verification,
  commitment/serialization equality and repeated challenge/count equality. All
  twenty isolated nonzero PoW witness mutations were rejected without panic.
- Locked offline Cargo metadata, formatting and strict native Clippy for the
  new example passed. These are recorded in `artifacts/native-gates-v1`; the
  checker commands and exact outputs are in `artifacts/checker-gates-v1`.

The repository's final integration gates remain the integration owner's
responsibility on the exact integrated commit; none of these observations is
represented as a gate on a later untested source tree.
