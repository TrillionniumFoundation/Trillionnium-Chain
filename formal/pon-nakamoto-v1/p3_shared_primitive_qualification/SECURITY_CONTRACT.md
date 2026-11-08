# P3 shared primitive: security contract

Status: **HOLD_NO_GO**. This is an independent research component on the
`cc836dfc13ef0006eb0878abd8cb5eca9a76bec0` lineage of PR #783. Its destination is
the existing research/integration lineage. It grants no consensus authority,
production activation, or security qualification.

## 1. Preserve the exact old finding

The old construction uses one fixed public Goldilocks Poseidon2 permutation
in the leaf sponge, the branch pseudo-compressor, and the duplex challenger.
For unrestricted pairs of four-field digests its raw branch operation is

\[
C(u,v)=\operatorname{prefix}_4(P(u\mathbin\|v)).
\]

For any digest `d` and distinct tails `r,s`, the inputs
`P^-1(d || r)` and `P^-1(d || s)` are distinct and compress to `d`.
The original native audit checked exact witnesses against locked P3 0.8.0.
It also established the fixed-role identities `H4(x)=C(x,0^4)` and
`H2(a,b)=H4(a,b,0,0)`.

These are failures of an *unrestricted compressor collision-resistance*
premise and an *independent leaf/branch function* model. They do not establish
two accepted conflicting W1 openings, a valid false W1 proof, or an attack on
the native W1 relation. The original audit remains an immutable historical
record: [integration](../w1_public_stark_research/security_model_audit/INTEGRATION.md).

The converse must not be claimed either. Failure to construct valid child
preimages is not a proof of binding. Authentication paths may contain
adversarial sibling digests with no supplied subtree. A security game must
match the actual verification interface, rather than restrict the adversary
to the output of the honest tree constructor.

The new [ordinary-path proposition](restricted_tree/RETAINED_CONSTRUCTION.md)
does give a conditional classical result for the retained construction. For
a uniformly random permutation on two halves of size `N = p^4`, fixed positive
leaf width `w`, fixed height `h` and index, let `b = ceil(w/4)` and
`T = Q + 2(b+h)`. Count every classical forward/inverse query across all shared
roles and all preprocessing in `Q`. If the initial advice is independent of
the sampled permutation and `T <= N^2`, the probability of two different
accepted rows at that fixed position is at most
`min(1, 2*N*T^2/(N^2-T+1))`. Siblings are arbitrary digest strings.

Its fresh-table argument distinguishes forward-origin and inverse-origin
entries, allows unrestricted inverse-created raw-compressor collisions, and
bounds the additional event needed for a conflicting ordinary path. This is
a new mathematical argument with a finite structural check, not a formal
proof-assistant artifact or external cryptographic audit. It does not cover
quantum queries, a fixed concrete Poseidon2, actual P3 pruned multi-openings,
or a Fiat-Shamir/PCS extractor. That retained-Poseidon2 statement is unchanged.

A separate [tagged-profile pruned-opening reduction](pruned_mmcs/BINDING_REDUCTION.md)
now covers the actual P3 0.8.0 binary, cap-zero verifier with fixed ordered
positive power-of-two matrix heights, widths and context. Two accepted
openings that conflict at a shared matrix-row coordinate yield a collision
among the complete framed-hash calls made by verification. It covers pruned
frontiers, shorter-row injections, arbitrary sibling digests and the pinned
extension flattening. The postprocessor also applies to quantum-produced
classical outputs, with at most `(q0+q1)*(h+2*k-1)+2` additional whole-hash
calls, including the witness recheck. This is a structural collision
reduction, not a quantum commitment extractor, a concrete primitive bound,
or a completed PCS/Fiat-Shamir security obligation.

## 2. Separate games and assumptions

| Game | Adversary output and fixed context | What would establish the claim |
|---|---|---|
| Raw compression collision | Any two distinct input pairs | Already broken for the old truncated permutation |
| Ordinary fixed-tree position binding | One root, one externally pinned tree shape and index, two accepted different row values; arbitrary siblings allowed | A reduction from the two paths to a collision in the actual encoded hash inputs |
| P3 multi-matrix opening binding | Pinned ordered matrix dimensions, cap policy, index reduction, extension flattening and full multi-opening frontier | A structural reduction for the tagged binary cap-zero power-of-two case is in [BINDING_REDUCTION.md](pruned_mmcs/BINDING_REDUCTION.md); concrete collision bounds and commitment extraction remain open |
| PCS binding and extraction | Actual FRI/PCS queries and adaptive commitments under the same primitive | The applicable classical/quantum extraction or knowledge theorem with all losses |
| Noninteractive W1 knowledge soundness | Both W1 components, actual transcript schedule, statement, preprocessing and parameters | A Fiat-Shamir/RBR reduction for the actual implementation and shared oracle interfaces |
| Lifecycle quantum security | All attempts, roles, recursive nodes, offline work and reused auxiliary states | A justified query/advice budget and composed failure bound for the specified experiment |

A deterministic collision extraction argument for two *already available*
classical paths does not establish a quantum extractor, collapsingness,
state-restoration soundness, knowledge soundness, or a proof for recursion.
The same applies to a finite enumeration on a deliberately small toy oracle.

If each component failure event has an applicable bound in the *same adaptive
experiment*, a union bound requires no independence. What is prohibited is
importing component bounds from incompatible oracle games, or giving each
shared role an uncharged fresh query allowance.

## 3. New-profile engineering contract

The candidate uses the complete standard SHA3-512 interface, injectively framed
messages, fresh version/component identifiers and distinct leaf, branch and
transcript hash domains. The W1 SHA-256 relation remains the relation being
proved. Replacing the host commitment/challenger does not prove a new recursive
verifier AIR or its cost.

The native implementation and retained profile specification are the authority
for exact byte order, digest representation, tags, contexts and wire shapes.
Do not infer extra position, height or tree-type tags that the implementation
does not supply. A fixed tree schedule or dimension check is different from
explicitly including those fields in every hash preimage.

New profile identifiers must be present before proof deserialization. The new
decoder must not reinterpret old proof bytes under a new hash, and the old
decoder must not reinterpret the new bytes under the old hash. The full
independent expected statement/context checks remain required. Truncation,
noncanonical field encodings, wrong shapes, trailing bytes and component
substitution must fail before any successful-verification outcome.

Input tags prove disjoint *encoded input domains*. They do not prove that
concrete outputs never collide, or that Keccak instances are independent
permutations. Leaf, branch and transcript still belong to one concrete
underlying primitive family and one adversarial accounting model.

The candidate is an offline research verifier. Structural decoding bounds and
sampled rejection times do not establish the original 0.25-core / 2-GiB /
zero-swap / 256-task / four-second / sixteen-hostile-request service contract.
No production ingress or fallback may be enabled by this experiment.

## 4. Applicable literature, with explicit boundaries

### Full sponge indifferentiability

[Alagic, Carolan, Majenz and Tokat (2025), Theorem 7.22](https://arxiv.org/html/2504.16887v2)
analyzes a complete sponge with quantum forward/inverse access to a uniformly
random permutation. Its query and maximum-message-length losses must be
retained. It is not a theorem that the fixed Poseidon2 or Keccak permutation
is random, and it does not apply directly to a full-width permutation followed
by truncation. Independent tagged domains can be studied through a joint
construction game; the theorem is not a license to silently replace every
concrete role by an unrelated random oracle.

### Precomputation and advice

[Carolan, Poremba and Zhandry (2024), Section 4 and Section 8](https://arxiv.org/html/2410.16595v1)
show that ordinary indifferentiability is insufficient for generic
construction-dependent precomputation. Their positive sponge application is
a one-round construction with rate at most capacity. It cannot simply be
imported as a theorem for this multi-round Merkle/transcript lifecycle.
Preprocessing charged as queries to the same fresh ideal permutation and free
construction-dependent advice are different assumptions. Classical bits and
quantum advice states must be identified explicitly, including setup timing
and reuse across proofs.

### Concrete ideal-permutation query arithmetic

[Carolan and Majenz (2026), Theorem 5.5](https://arxiv.org/html/2609.28469v1)
is a preprint giving explicit ideal-permutation sponge bounds. The accompanying
calculator evaluates its stated inequalities using exact rational arithmetic;
it does not independently verify the paper's proof. The parameters include
digest length, rate, capacity, all forward/inverse queries and the total padded
length of output candidates. The fixed-target preimage condition and query
convention are mandatory. This is a single-event construction bound, not a
Merkle extractor, Fiat-Shamir theorem, or concrete Keccak certificate.

### Fiat-Shamir remains a separate obligation

[Chiesa and Orru, A Fiat-Shamir Transformation From Duplex Sponges](https://eprint.iacr.org/2025/536)
studies an explicitly specified transformation and identifies why ordinary
indifferentiability alone is insufficient for knowledge soundness and zero
knowledge. A hasher replacement in the P3 challenger is not evidence that
this transformation or its hypotheses have been implemented. The actual
observation order, codecs, sampling, grinding, RBR assumptions and extractor
losses remain part of the project's proof obligation.

### Upstream challenger advisory applicability

The official [CVE-2026-46654 advisory](https://github.com/Plonky3/Plonky3/security/advisories/GHSA-vj64-rjf3-w3v7)
identifies `MultiField32Challenger` and fixes in P3 0.4.3/0.5.3. This tagged
candidate pins P3 0.8.0 and configures
`SerializingChallenger64<Goldilocks, HashChallenger<u8, TranscriptHasher, 64>>`;
it does not select the advisory's `MultiField32Challenger` path. The advisory
therefore does not establish a forgery of this configured W1 candidate.
This applicability check is not a Fiat-Shamir proof. The separate inherited
HashChallenger observation/partial-consumption aliases documented in
[PROFILE.md](PROFILE.md) and their native regression tests remain relevant.

[NIST FIPS 202](https://csrc.nist.gov/pubs/fips/202/final) specifies SHA3-512.
Selecting that standard algorithm does not constitute validation of this
application's implementation or protocol.

## 5. Required lifecycle ledger semantics

The future adversarial budget must distinguish:

1. Initial state independent of the sampled ideal primitive, versus advice
   depending on the deployed public construction.
2. Pre-setup and post-setup work, with every counted primitive evaluation in
   the same total query budget.
3. Forward and inverse queries; classical and quantum query conventions;
   and hash-call expansion into actual permutation calls.
4. All shared roles and both proof components, failed or abandoned attempts,
   rejected proofs, offline searches, parallel workers and recursive nodes.
5. Advice size, generation cost, persistence, reuse and external public-help
   channels, including whether an asserted bound is observed or assumed.

Honest native call counters provide measurements of those executions. They
cannot establish an upper bound on an adversary's lifetime queries or certify
the absence of unobserved advice. A calculation with declared inputs is a
conditional model evaluation. Unknown premises remain unknown.

## 6. Qualification fields

All of the following remain unqualified until the corresponding evidence and
theorem actually exist:

| Field | Current claim |
|---|---|
| Concrete old restricted-tree binding bits | Unknown; conditional classical ideal-permutation ordinary-path proposition is separate |
| Concrete new-profile binding bits | Unknown |
| Shared-primitive quantum model reduction | Open |
| Precomputation/advice coverage | Open |
| Full W1 noninteractive knowledge bound | Open |
| Quantum lifecycle error and PQ128 qualification | Unknown / false |
| Recursive verifier AIR and full backend cost | Unmeasured for this new hash profile |
| Production service and Node admission | Not qualified by this work |

An implementation test, a known-answer vector, a successful proof, or an
ideal-model probability calculation must not set any of these fields to a
security acceptance value.
