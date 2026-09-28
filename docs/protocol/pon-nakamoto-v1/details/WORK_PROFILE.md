# W1 — executable neural-work profile

Normative scope: `pon-matmul-transcript-64-v1`, experimental only. Configuration is
[`work-profile-v1.json`](../../../../config/pon/work-profile-v1.json); it is included in
the genesis parameter commitment. Source changes alone cannot hot-swap its semantics.

The Rust relation is `trnm-crypto-primitives/src/pon_work.rs`; a separately coded Python
oracle is `formal/pon-nakamoto-v1/work_oracle.py`. They share bytes and vectors, not an
implementation. Both were authored in this development increment. Cross-language
agreement is not external independent security acceptance.

## W1.1 Exact arithmetic and byte grammar

Let n=64, r=8 and q=4,294,967,291. Every field element is a canonical little-endian u32
strictly below q. No floats, NaN, signed zero, decimal aliases or approximate equality
are accepted. Products and sums use u128 in Rust, exact integers in the Python oracle.
A sum has at most 64 products before reduction; its maximum fits u128. Matrix indexing
is row-major. Decoding rejects before multiplication if length, magic or element range
is invalid.

Define H(tag,parts) as SHA-256 of:

    "TRNM-PON1\0" || LE16(tag byte length) || tag
       || concat(LE32(part byte length) || part)

Inputs are A and B, each 64×64. TaskId=H("task",LE32(A),LE32(B)). Work eligibility is
looked up in the PARENT state, not state produced by the block being mined.

The proof has exactly 49,188 bytes:

| Offset | Bytes | Meaning |
|---:|---:|---|
| 0 | 4 | ASCII PNW1 |
| 4 | 16,384 | A, 4096 canonical field elements |
| 16,388 | 16,384 | B |
| 32,772 | 16,384 | decoded useful product C=AB |
| 49,156 | 32 | transcript digest t |

No extension, optional field or trailing bytes is accepted. The certificate contains
all matrices needed for historical work verification; a verifier does not need to fetch
an old private training set or a mutable remote model file to verify this relation.

## W1.2 Challenge-dependent encoding

The exact 318-byte header is defined in [LEDGER_WIRE.md](LEDGER_WIRE.md).
Challenge c=H("challenge",header). For labels 0,1,2,3, concatenate
H("noise",c,label-as-one-byte,LE32(counter)), counter starting at zero. Read each hash
as eight LE32 words and discard values >=q. Take the first 512 accepted values per label.
They define EL(n×r), ER(r×n), FL(n×r), FR(r×n), respectively. At most128 hash
blocks per label may be consumed; insufficient accepted words reject NOISE_BUDGET.
The bound prevents an unbounded rejection-sampling path and is committed in the profile.

    A' = A + EL ER   (mod q)
    B' = B + FL FR   (mod q)

Set C' to zero. Initialize SHA-256 with `TRNM-PON-TRACE1\0 || c`. Loop block indices
bi, bj, bk in 0..8, in that order. Within each triple, visit i in [8bi,8bi+8) and j in
[8bj,8bj+8), in that order. Update:

    C'[i,j] = (C'[i,j] + sum(A'[i,k] B'[k,j], k=8bk..8bk+7)) mod q

Append this updated cell as LE32 to the transcript hash immediately. The final digest
is t. Every partial tile accumulation contributes; final product bytes alone are not
a substitute for the transcript. Decode useful work with the exact identity:

    C = C' - (A FL) FR - EL (ER B')   (mod q)

This equals AB. The profile does not claim that computing this identity proves all
training, model quality, provenance, ownership or data-use permissions.

## W1.3 Lottery, identity and verification order

Ticket=H("ticket",c,t). Treat ticket and target as unsigned big-endian 256-bit values;
accept the threshold iff target>0 and ticket<=the branch-derived expected target.
BlockId=H("block",header,t). Randomized proof bytes, miner comments or serializer choices
cannot provide additional accepted lottery outputs. Changing any header field changes c.
The block identifier is not inserted back into its own application post-state.

Verification order: exact length/magic → bounded field decode → expected TaskId → cheap
ticket filter → full transcript replay → exact decoded C → full block application rules.
Only all checks can construct the native non-public `VerifiedWork` fields. A decoded
object or a passing cheap ticket is not authority. Verifier caches key the complete
profile, expected challenge, task and certificate identity; a cache hit creates no work.

The same already trained parameters can be reused as input to fresh challenges. They
cannot be counted as fresh training themselves. A different header requires a new valid
transcript. Retransmitting the identical statement is one block, not a second reward.

## W1.4 No header/output fixed point

Application execution and its state/receipt roots use the parent state, included native
transactions and a fixed subsidy/fee rule. Current work output is NOT inserted as a new
artifact or receipt into the same block. A newly discovered useful product/model may be
submitted in a later transaction. `register_work` also affects only later blocks.
The reward key is H("reward",parent,height,miner), not the current block hash or trace.
Thus template → challenge → transcript does not point back into template construction.

## W1.5 Useful model arithmetic

The concrete model experiment maps signed integers into Fq. Features are bounded by 128,
weights by 32,767, and each demonstrated contraction has 64 coordinates. Therefore the
absolute ordinary-integer result is below q/2. Decode v as v-q when v>q/2, otherwise v.
This exactly recovers the ordinary signed product. The supplied experiment actually uses
clipped-8 features; it proves a specified 64-coordinate part of one selected expert.
It is neither a whole-model training proof nor evidence that adding parameters improves
quality. The model/evaluation profile is specified separately.

## W1.6 Security claims, measured failure and activation boundary

This is a full-recomputation experimental profile, not a succinct proof system. It is
inspired by challenge encoding and transcript ideas from Komargodski–Weinstein,
*Proofs of Useful Work from Arbitrary Matrix Multiplication*, arXiv:2504.09971v4.
Their conjectured hardness does not become a theorem for this implementation, and this
implementation does not claim their asymptotically optimal overhead or practical cost.

Explicit remaining obligations: adversarial transcript shortcuts, preprocessing across
challenges, task-dependent cost, hardware/pooling advantage, early termination, uniform
independent lottery behavior, cheap maintenance instances, and parameter-size scaling.
The decoder can exploit some structured inputs without reducing all transcript work;
measuring the honest implementation is not a lower bound on an adversary's cost.

A concrete unresolved admission attack is already measured: a sender cheaply fabricates
a transcript digest that passes the ticket threshold, while rejection requires a full
recomputation. Queue/connection limits bound local damage but do not prove Sybil-safe
admission. `pon_cost` measures valid generation, valid verification, invalid verification
and cheap forgery separately. This prevents public-network activation until a reviewed
admission/proof construction and threat model remove or adequately bound amplification.

Required vectors cover canonical product identity, every changed header context, false
product, false trace, malformed length/field, zero matrix with a forged trace and native
versus Python byte identity. Reference evaluation is executable; hardness and external
acceptance remain false. No old BFT or hash-only fallback fills that gap.
