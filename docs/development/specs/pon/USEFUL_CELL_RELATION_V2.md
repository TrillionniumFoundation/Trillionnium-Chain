# Useful Cell postprocessing relation v2

Profile: `pon-useful-cell-int257-postprocess-research-v2`.
Status: executable research specification with bounded canonical transport and
full native verification. This explicitly changes the work relation. It is not a
registered chain work profile, W1 replacement, succinct proof, model adoption or
activation proposal.

## Existing implementation reused

The [new reference](../../../../formal/pon-nakamoto-v1/useful_cell_v2/src/lib.rs)
links the existing
[routed int257 grouped operator](../../../../trillionnium/crates/trnm-crypto-primitives/src/pon_routed_int257_grouped.rs)
through its actual Cargo package. It calls `PreparedModel::observe` for the
packed producer, `observe_direct` for the direct selected producer and `verify`
for the independent original-coefficient scalar check. No copy of its matrix
implementation or hash primitive is substituted.

The preceding [grouped operator v0](GROUPED_CELL_OPERATOR_V0.md) and
[useful Cell relation v1](USEFUL_CELL_RELATION_V1.md) remain valid in their original
namespaces. In v1, runtime quantization and STOP are disabled. Here they are
explicit parts of a new consumer-selected policy. Existing source replay,
model artifact validation and independent expected-contract ownership remain
separate prerequisites for a source-backed consumer. The new JSON loader
validates the specified bytes; it does not itself replay the source corpus or
validate a model artifact's external provenance.

## Exact one-step relation

A task independently retained by the consumer contains:

| Part | Bound values |
| --- | --- |
| Linear model | Original base, router and three delta matrices, all `3 x 257`, with their existing model version and commitment |
| Ordered requests | IDs, scopes, arrival/deadline values and all 257 signed features for each of 1–64 requests |
| Context | Chain, parent, challenge and batch ID |
| Before state | Cell ID, unsigned generation, snapshot root and the same model commitment |
| Provenance and use | Program, extractor and source-input digests; consumer, allowed-use and candidate-artifact digests |
| New policy | Quantization shift, symmetric clamp, activation and STOP rule |
| Contract window | Inclusive issue time and exclusive expiry time |

The typed `TaskContract` validates once and keeps its fields private. The verifier
receives that expected object from its caller. A producer cannot choose the
verifier's expectation by putting a new contract ID in its claim. A caller that
constructs an expectation from untrusted producer data has not established
independent admission; hash equality cannot repair that trust error.

### 1. Router and rectangular selected operators

Let `X` have shape `257 x b`, with `1 <= b <= 64`. Original weights lie in
`[-32767,32767]`, features in `[-8,8]`, and feature 256 is exactly 8. Products and
sums are exact signed integers in i64. The router computes `S = R X`; request
`i` selects the lowest expert index attaining `max_e S[e,i]`.

For each expert `e`, `G_e` lists the request indices selecting that expert in
strictly increasing original request order. The three lists form a disjoint,
complete partition. Gather `X_e` has its actual rectangular shape `257 x |G_e|`.
The selected operator computes `(B + D_e) X_e` with output shape `3 x |G_e|` and
scatters it back to the original order. Empty groups have no selected product.
There is no square padding and no second routing pass.

Each original router or base/delta dot product has absolute bound 67,368,952;
the merged selected output has absolute bound 134,737,904. The native verifier
independently accumulates the original base and selected delta, instead of
trusting the producer's cached merge or packed gather. It also checks all router
scores, every route, original raw predictions, group membership/order and
accounting values. Accounting is descriptive and confers no work credit.

### 2. Quantization and activation

For each raw selected output `z`, let `d = 2^shift`, where `0 <= shift <= 30`.
The policy also specifies `1 <= M <= 32767`. Compute:

- `q = trunc_toward_zero(z / d)`;
- `r = z - d*q`, with `|r| < d` and nonzero `r` having the sign of `z`;
- `c = max(-M, min(M, q))`;
- `a = c` for `Identity`, or `a = max(0,c)` for `Relu`.

There is no floating-point operation, stochastic rounding or implementation
choice about a negative right shift. For example, `z=-7, shift=1` gives
`q=-3, r=-1`; arithmetic right-shift semantics would produce a different result.
The claim includes `q`, `r`, `c` and `a` for all three classes and all requests.
The verifier recomputes and compares every intermediate.

The output prediction is the lowest class index attaining the maximum activated
value. Quantization, saturation and activation can create new ties and change a
prediction. Such changes require separate model-quality evaluation; matching
arithmetic alone supplies no evidence of accuracy or usefulness.

### 3. Terminal decision

Let `m` be the maximum activated value minus the largest activated value among
the other two classes. Thus `0 <= m <= 65534`, including `m=0` for a top tie.
`Disabled` produces `stop=false`. `MarginAtLeast(t)`, for `1 <= t <= 65534`,
produces `stop=(m >= t)`. Equality stops. The threshold and enabled/disabled tag
are part of the expected task. This integer margin is not a calibrated
probability or a safety score.

STOP is a per-request terminal-decision output of **this one Cell step**. All
requests in the admitted batch still require their complete linear and
postprocessing results; an earlier STOP does not permit cropping the batch. A `false` value
is a continuation recommendation, not a proof of a subsequent step. The profile
does not execute or certify a mutable Cell loop, a scheduler or future
continuations. The after state must equal the complete before-state tuple,
including generation and snapshot root. Even a correct STOP decision cannot
advance state or authorize adoption, payout, CURRENT or FinalUse.

### 4. Commitments and result recovery

New commitments use the repository's existing `hash_domain` framing and SHA-256:
`pon-useful-cell-input-v2`, `pon-useful-cell-contract-v2` and
`pon-useful-cell-statement-v2`. Each includes the exact new profile string.
Original model and grouped statement commitments remain in their original
namespaces and are included inside the new claim.

Input bytes are context hashes in chain/parent/challenge/batch order, a big-endian
u16 request count, then each request's ID, scope, u64 arrival, u64 deadline and
257 big-endian signed i32 features. Contract bytes contain the full state,
provenance/use fields, policy and window. `Disabled` has one unique encoding:
a zero tag followed by four zero bytes. The contract hash also binds the input
commitment; its state includes the original model commitment.

The complete claim includes every router score, route, original-order raw
output, raw prediction, ordered group index, accounting field, all postprocess
witnesses, terminal decisions and after state. Consequently result recovery
needs no random opening or omitted tile. Full output bytes are retained and
compared; hashes provide binding, not verification of the arithmetic.

## Canonical transport and bounded decoding

The [binary codec](../../../../formal/pon-nakamoto-v1/useful_cell_v2/src/lib.rs)
accepts one exact layout:

| Field | Bytes |
| --- | ---: |
| Magic `UCELLV2` plus zero byte, request count | 8 + 2 |
| Contract ID, complete after state | 32 + 104 |
| Original model/input/statement commitments | 96 |
| Each linear result (scores, route, logits, prediction) | 50 per request |
| Three group counts plus their indices | 6 + 2 per request |
| Dense MAC count, padded count, nonempty-group count | 17 |
| Each postprocess witness | 78 per request |
| New statement commitment | 32 |

Integers are big-endian, signed values use two's complement, hashes are 32 raw
bytes, and STOP is exactly byte 0 or 1. Total length is exactly `297 + 130*b`,
at most **8,617 bytes**. The decoder checks that count-derived length before
vector allocation, then bounds every group count/index and all class/expert
indices. It rejects unknown magic, invalid booleans, truncation and trailing
bytes. These controls bound this frame's parse/allocation work; they are not a
network admission service or a global verification CPU budget.

The [task JSON loader](../../../../formal/pon-nakamoto-v1/useful_cell_v2/src/task_json.rs)
is bounded to 256 KiB, has exact field sets, strict integer/hash/shape checks and
requires the exact sorted-key compact representation produced by its pinned
`serde_json`. Reserialization equality rejects duplicate keys, whitespace and
alternate spellings. Task JSON is a research transport; the canonical
cryptographic encodings are the binary encodings above.

## Verification and deadlines

Verification checks the caller's model/contract/state/shape first, then calls the
existing independent scalar verifier, checks all new numerical and decision
constraints and recomputes the new commitment. It samples the caller's clock
again before returning a privately constructed `VerifiedCell`. Both contract and
request deadlines are exclusive; a regressing clock is rejected.

The Unix file CLI opens inputs with `O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC |
O_NOCTTY`, then checks the same descriptor is a regular file and within its
length bound. This closes the FIFO open/read blocking path and the check-path /
open-path replacement race. Final-component symlinks and special files are
rejected, as are length changes detected across the read. Non-Unix file input
fails explicitly. Regular-file I/O can still wait in the filesystem/kernel;
these checks are not a hard real-time I/O or worker-preemption guarantee.

The CLI adds measured monotonic elapsed time to the caller-supplied clock origin,
including file parsing and verification. The caller still owns that origin and
all deadlines. A completion-time check does not preempt a cryptographic call,
authenticate time or reserve a later consumption right. Recheck currentness and
deadlines at the original effect/consumer boundary. State mutation and
continuation proofs are deliberately outside this profile.

## Dedicated-proof obligations still open

This implementation is an executable full relation and native correctness
reference. Verification is full recomputation: router and selected expert work
remain proportional to the complete batch. The witness is not a succinct proof,
a sound sumcheck transcript, a GKR proof or a proof of mining difficulty.

A later algebraic proof must bind the original matrices and request vectors,
prove all router outputs and lowest-index choices, authenticate the complete
ordered partition/gather/scatter and prove each actual rectangular selected
matrix product. The quotient/remainder, range, sign, saturation, activation,
argmax and STOP constraints must join the same task and state commitments.
Neither linear equality alone nor a few opened requests proves this relation.

Signed integer embedding needs explicit ranges. A field modulus exceeding twice
the raw-score bound only makes those signed scores uniquely representable; it
does not automatically exclude wraparound in every residual of a combined
constraint. Each gate needs a proven integer bound, or limb/carry/range
constraints. In particular, `d*q+r` and comparison gadgets need their own
analysis. A different proof-library field cannot silently replace integer
semantics. No field conversion, algebraic proof backend or Fiat–Shamir security
argument is claimed here.

No lottery or extra hash-only work has been added. Selecting a chain work
relation, proving its minimum legal cost and upgrading consensus require
separate protocol decisions. W1's full prefix and ordered SHA-256 trace remain
their original task, not a property inherited by this v2 Cell relation.

## Reproduction and evidence

The [runner and instructions](../../../../formal/pon-nakamoto-v1/useful_cell_v2/README.md)
provide independent task files, complete binary claims and separate producer and
verifier processes. The reproduction script reuses the existing Python scalar
control and independently encodes every byte, then compares it with both native
producer kernels at batches 1, 4, 16 and 64. It includes a rehashed false-STOP
claim and a different-consumer expected-task negative control.

Synthetic fixtures exercise the existing Cell's actual operator shapes. They do
not constitute replayed real demand, source-corpus provenance, learned-model
quality evidence or an ordinary Hepta adoption result. The exact validation
record and preserved environment failures are in the
[validation record](../../../../formal/pon-nakamoto-v1/useful_cell_v2/VALIDATION.md).
