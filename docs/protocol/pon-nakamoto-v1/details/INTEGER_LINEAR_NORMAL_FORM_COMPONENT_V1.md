# Exact integer linear normal-form component v1

Status: isolated M11 development component; consensus admission, model utility,
rewards, source independence and production activation are all false. Existing
PNX1 tag6 and every signed/stored schema are unchanged. No registry profile is
enabled by adding this component. No new package, local dependency edge, typed
operation, authority, store or global cache is introduced.

## Exact accepted boundary

The owner is `trnm-verification-profiles` (M11), existing
`M11.EvaluateFrozenModel` / `M11.AdmitEvaluation` verification boundary. Public
API is `exact_integer_linear_v1::IntegerLinearContextV1` plus
`verify_integer_linear_v1` returning private-field
`CheckedIntegerLinearUpdateV1`. Its equality method compares full context and
all 771 output coordinates; the hash is a compact identifier after computation.

The component accepts canonical JSON bytes of the existing Python contract and
adapter in `formal/pon-nakamoto-v1/model_attribution.py`. It pins the installed
integer-linear family ID, caller-supplied parent artifact ID, slot 0..2 and
numeric `exact-BA-no-rounding-fixed-router-add-to-delta-v1`. It does not load or
authenticate the parent: a future caller must obtain that pin from the existing
parent/model verification owner. Scale is fixed at 1024. Other scale/family/
numeric declarations are refused, never compared or merged under this profile.

Contract bytes are exactly 372 bytes (two lowercase 32-byte digest strings and
single-digit slot). Adapter input is 660..32768 bytes, rank 1..8, A rank×257,
B 3×rank, at most 2080 factor coordinates. Each factor is an integer in
[-32767,32767]. The closed parser refuses extra/duplicate/out-of-order fields,
whitespace, escaped digest encodings, trailing bytes, noninteger kinds, leading
zeros, negative zero, malformed shapes and unsupported versions. Parsing depth
is fixed; allocation follows declared fixed maxima rather than an unchecked
length. The bounded example reads at most limit+1 bytes before refusal.

For each i,j, compute `sum_k B[i][k]*A[k][j]` in ascending k using checked i64
multiply and checked i64 add, then require the completed value within
[-32767,32767]. The maximum permitted intermediate magnitude is
8×32767²=8,589,410,312, so valid-input i64 overflow is impossible. Large
intermediates may cancel; using checked i32 would incorrectly refuse valid
factorizations. Out-of-bound/oversized attacker integers are refused before
product execution. The arithmetic-overflow helper test is defense in depth for
internal impossible-under-valid-bounds operands, not evidence that an accepted
factor witness can overflow i64.

Declared work is exactly 3×257×rank (771..6168 products), including zeros. A
caller may supply an exact bounded product budget within that range. This is an
arithmetic-operation bound, not measured CPU cost, minimum mining work, energy,
parallel process RSS, a deadline certificate or an economic cost lower bound.

The canonical normal object is the existing Python
`pon-normalized-linear-update-v1`, with complete contract ID and 3×257 delta.
All three IDs use the original TRNM-PON1 H framing (domain length LE u16 and each
part length LE u32) and original contract/adapter/normalized-update domains.
Raw-factor artifact ID and full-update fingerprint are separate: invertible
integer basis changes, paired sign changes and zero-rank padding can produce
different canonical artifact bytes and the same normal form. External source
keys do not enter the declared update ID. This component does not authenticate
sources or merge admitted-source budgets; the existing Python bounded grouping
owner still handles those separate inputs.

## Reproducible component entry point

Build only the M11 package and run the local example:

```sh
cargo build --offline --locked --release -p trnm-verification-profiles --example integer_linear_normal_form
integer_linear_normal_form CONTRACT.json ADAPTER.json --max-multiplications 6168
```

Exit 0 prints the recomputed full normal vectors, IDs, rank and exact operation
counts; exit 2 is explicit refusal. It does not open a Node/store, sign a message,
submit a transaction, train an LLM or issue a reward. Actual Python parity
controls compare every coordinate and all original IDs against unchanged
`normalize_adapter`, preserving each command, stream and refusal. Random finite
test vectors are ordinary component controls, not held-out quality evidence.

## Concrete integration proposal and unresolved wire boundary

First integrate only as an optional explicit M11 verification backend whose
input binds an independently verified current parent artifact and exact slot.
Do not trust a caller-provided fingerprint, adapter hash, probe predictions or
claimed source identity in place of factors. Do not reinterpret native tag6:
its current interpretation carries no complete factor witness and this isolated
component is not wired into native adoption/deduplication/settlement.

A future signed witness must define a fresh version, payload, registry policy,
model family/parameters and network/genesis namespace. The existing per-PNX1
2048-byte limit leaves at most 1889 payload bytes after the 159-byte envelope.
Rank8 canonical JSON witnesses are often too large. Even rank1 JSON can exceed
1889 bytes when many coefficients use six characters, so merely promising
rank1..2 JSON does not solve inclusion. A separately specified fixed-width
signed-i16 witness would need 260×rank×2 = 520×rank factor bytes; rank1..2 plus
explicit context metadata is potentially encodable, subject to exact payload
and fee proof. Its codec, signed domain, admission semantics, hash binding,
parent checks, clone/source-budget rule, adoption and reward policy are future
engineering work requiring actual negative/native lifecycle tests. No such
codec is silently supplied by this v1 JSON component.

Equal BA implies equal declared linear updates for every input under identical
parent/slot/numeric context. Unequal BA need not imply different argmax/router
classifications, and matching probe classifications does not prove equality.
Complementary distinct updates remain separate; their sum can be checked but
this component does not assign credit or prove marginal gain. This is not
FP32/FP16 LoRA equivalence, arbitrary neural-circuit equivalence, a global
optimum certificate, genuine positive LLM efficacy or a public readiness gate.
