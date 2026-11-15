# WLC1: work-lifecycle observation, provenance, and finite public help

**Research only; no native or MU1 activation.** This addition audits the actual
frozen MU1/W1 hash composition, authenticates bounded observation records with
real ML-DSA-65 signatures, and proves a finite-classical-help reduction for the
existing conditional ideal-query bound. It preserves MU1 version 1 byte for
byte. It does not establish a global physical resource budget, a fresh initial
state, or a native confirmation probability.

The distinction that controls every API here is precise: an externally pinned
signature can authenticate a recorder's statement; a complete, anchored list
can prevent alteration of that signed list; neither fact proves that the list
contains all computation, all public help, or all previously retained state.

## 1. Actual hash composition and a concrete receipt counterexample

The frozen implementation is
[mandatory_units_relation.py](mandatory_units_relation.py), which uses the
existing full [W1 native relation](../../trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs).
These are actual SHA-256 computations, with the following domains.

| Computation | Actual framing and role |
| --- | --- |
| MU1 contexts, unit challenges, output leaves, ordered root, identity, final ticket | `TRNM-PON-MU1\0`, length-framed fixed tags and parts |
| W1 task, noise expansion, unit ticket, native verification receipt | `TRNM-PON1\0`, length-framed fixed tags and parts |
| W1 cumulative full trace | `TRNM-PON-TRACE1\0`, challenge, then the specified ordered tile stream |

MU1's final ticket is exactly SHA-256 of

```text
"TRNM-PON-MU1\0" || LE16(6) || "ticket" ||
LE32(32) || context_digest || LE32(32) || ordered_units_root
```

The observer reconstructs these exact bytes from a previously frozen complete
MU1 winner and verifies that their actual SHA-256 output equals the ticket.
Distinct tags create different encoded input strings; they do not prove that
different computations using the same public SHA-256 algorithm are independent
random functions. The ideal terminal oracle of the query theorem is still an
explicit idealization. No preprocessing-aware reduction for this actual
composition has been established.

The existing [pon_work_io](../../trillionnium/crates/trnm-crypto-primitives/examples/pon_work_io.rs)
`verify` operation runs full W1 verification and, if successful, returns

```text
H_W1("native-work-verification"; entire_verifier_input)
```

This is an **unkeyed**, public digest. The new control
`public_receipt_without_verification` computes it without invoking W1 or a
native child. For valid work it produces exactly the native output. For a
one-byte-invalid trace it still produces a well-formed 32-byte value, while
the real native verifier rejects the same input with exit 2 and `WORK`.

This is a counterexample to treating the digest alone as an execution or
resource attestation. It is not a bypass of a correctly invoked trusted native
verifier: that verifier still performs the complete relation before returning.
The old wrapper's trust in the selected executable remains relevant. WLC1 also
rechecks full W1 artifact predicates, so even a signed claim of successful
execution with a fabricated receipt for invalid work is refused.

## 2. What observation can and cannot determine

Let `O(h)` be everything retained by a local recorder from execution history
`h`: invocations it saw, inputs/outputs it retained, source hashes, elapsed
readings, imported packets, signatures, and published checkpoints. Suppose
an allowed participant can do additional work before this recorder starts,
or on an unobserved machine, without changing these local observations.

For a history `h_0`, append arbitrary such preparation to obtain `h_r` while
preserving `O(h_r)=O(h_0)`. Global work/query expenditure and hidden inventory
can differ even though the entire signed local record is identical. Therefore
no finite number computed solely from `O(h_0)` is a sound upper bound on all
those histories' resources or retained work. The record can be truthful and
the cryptography sound; the missing information is coverage.

The concrete observation reproduces this boundary with a real full-size MU1
winner imported from the prior frozen evidence. A source observer explicitly
records that pre-existing packet and context as **unmetered imports**, performs
actual complete native unit verification, and publishes the packet. A second
observer imports it through a signed source reference and verifies it again.
These are real validation operations. They do not recategorize earlier
generation as fresh work or certify an empty initial state.

A new signature, session identifier, subprocess, reset, or nonce does not
remove information already held outside the recorder. Current SHA-256 is a
public function and can be evaluated outside this process. There is no
mandatory oracle broker, trusted whole-world monitor, or hardware attestation
in this addition. Complete physical resource coverage remains unproved.

## 3. New WLC1 namespace and exact authentication scope

The implementation is [work_lifecycle_certificate.py](work_lifecycle_certificate.py).
The fresh observation namespace is:

```text
domain:     "TRNM-PON-WLC1\0"
schema:     "pon-work-lifecycle-observation-v1"
checkpoint: "pon-work-lifecycle-checkpoint-v1"
purpose:    "signed-observations-no-resource-or-consensus-authority"
algorithm:  "ML-DSA-65"
```

WLC1 uses FIPS 204 pure ML-DSA-65 with an empty ML-DSA context. The domain is
inside the signed message; there is no prehash/raw-mu signing shortcut and no
Ed25519 or other fallback. Public keys use the repository's exact 1,974-byte
ML-DSA-65 DER SPKI: its 22-byte fixed prefix followed by the 1,952-byte key.
The existing key identity is

```text
SHA256("TRNM/PoN/PQKey/v1\0" || exact_SPki_bytes)
```

The 3,309-byte signatures are produced by the installed cryptography/OpenSSL
implementation and independently checked by the existing RustCrypto
[pq_message_oracle](../../trillionnium/crates/trnm-crypto-primitives/examples/pq_message_oracle.rs).
This is reuse of an existing signature algorithm, not a new cryptographic
primitive. Its security is an assumption; passing test vectors is not a
proof of unforgeability or a claim of key-custody qualification.

### 3.1 Canonical records and checkpoints

Canonical JSON has ASCII strings, sorted keys, compact separators, exact
integers in the declared range, no floats/nonfinite numbers, and strict
duplicate-key rejection. Unknown fields are refused. The signed semantic
representation is canonicalized; insignificant input JSON whitespace is not
a new signature message or a new work identity.

For a fixed ASCII tag and canonical JSON bytes `J`, the internal digest is

```text
SHA256("TRNM-PON-WLC1\0" || LE16(tag_length) || tag || LE32(len(J)) || J)
```

The header binds the fresh namespace, purpose, session, signer key ID,
algorithm, unchanged MU1 relation-parameters digest, source commit, exact
source/binary hash declarations, and declared finite-help policy. It fixes
`initial_state_certificate = null` and
`complete_mediation_attested = false`. Attempts to promote either field to
an unsupported authority claim are refused.

For this experiment `source_commit` names the baseline anchor
`f8362822b406463ac3dfcc911a0c3eda1686e32d`. It does not assert that the newly
added WLC1 files existed in that baseline commit. Their exact executed
contents are bound separately by `source_manifest`; the final evidence
checks those file hashes. Neither field is a reproducible-build or runtime
attestation linking source to a process image.

The header digest is the genesis head. Every event has exactly
`sequence, previous, kind, body`. Sequence starts at one, is contiguous, and
its previous field equals the previous event digest. The final head and
event count are sealed. Checkpoint statements bind the schema, purpose,
session, header digest, signer key, sequence, head, and closed status. The
signature message is

```text
"TRNM-PON-WLC1\0" || "checkpoint\0" || LE32(len(J)) || J
```

Both the initial checkpoint and final closed checkpoint must verify against
the **caller-supplied expected public key and exact endpoint pins**. The
verifier does not adopt a public key or final endpoint just because an
untrusted document provides one. Its result means the supplied expectations
matched; their real-world authorization and independent retention are not
manufactured by this API.

### 3.2 Source chain and artifact semantics

| Event kind | What is checked |
| --- | --- |
| `native_call` | Declared program hash is in the pinned header; retained input/output/stderr bytes match hashes and lengths; successful prove/verify artifacts pass the complete existing W1 predicate; verify receipt matches the exact input |
| `mu1_observation` | Complete context/packet artifacts are present; actual hashes and identity recompute; full frozen MU1 acceptance/refusal equals the recorded result |
| `publish_artifact` | Exact retained artifact bytes match the committed hash and extent; a complete-work label also requires an earlier full predicate recheck in this source fragment |
| `help_delivery` | Actual retained payload fits its predeclared slot alphabet; any signed source reference recursively verifies against separately supplied source pins and an exact published artifact |
| `unmetered_import` | Artifact bytes are retained and bound; their earlier cost or opaque-state content remains unmetered |
| `resource_reading` | A bounded integer reading with literal direction `observation_only`; an upper-bound promotion is refused |

The verifier follows a bounded acyclic source graph. A reference binds the
source label, header digest, final head/count, and the exact publish event.
Every linked source's signatures and event chain are actually verified.
Missing sources, changed source artifacts, false `signature_valid` booleans,
untrusted substitute public keys, and cyclic/deep graphs do not supply an
alternate successful route.

Each collection uses independently supplied expectation pins. In this
experiment both recorder keys are generated by this one laboratory process,
kept in memory, and never serialized/exported. The output contains public
keys and signatures only. Different keys do not establish independent
administration. Accordingly `real_independent_trust_root_established` stays
false even though the actual signatures verify.

### 3.3 The limited authenticated-prefix theorem

Assume the external endpoint/key pins are authentic, the signature scheme is
unforgeable for the adversary under consideration, and the digest commitment
has the required collision/second-preimage security. An accepted collection
authenticates the stated endpoints and the canonical event fragments between
them. Altering an event while preserving the fixed later chain/head requires
a digest commitment break; substituting a different signed endpoint/key
requires a pin change or signature failure. Missing first/middle/last events,
reordering, duplication, and truncation violate extent or chain checks.

If the verifier instead accepts a new end pin from the untrusted sender, a
validly signed earlier prefix is not distinguishable from intentional
truncation. This is why the exact final pin is external. Durable retention of
that pin outside chain reorganization and revocation/owner rotation requires
its own owner; no such production owner is added here.

The theorem concerns **signed statements and declared fragments**. A signer
can sign a false execution story. A source hash is not a proof that its
corresponding source produced a particular executable or that an OS ran it
faithfully. No process launch, timer, memory reading, or observer signature
proves global coverage, secret state erasure, or all-algorithm minimum cost.

## 4. A new strict finite-classical-help reduction

The previous MU1 theorem paid all relevant helper terminal queries or required
a justified joint initial recording-tail certificate. There is another
restricted way to account for public help: pay for the complete finite
information interface instead of pretending that unknown helper preparation
cost was measured. This can be useful only when the **global** interface
alphabet is small enough.

### 4.1 Assumptions

Let `F` be the ideal terminal oracle used in the frozen MU1 query theorem. Let
the receiver execute a possibly quantum algorithm and interact with helpers.

1. At the start of the receiver's charged strategy its entire non-helper
   state is independent of `F`. All later oracle-dependent external influence
   is either included in its own charged queries or received through the
   classical interface described below. There is no uncounted correlated
   initial state, no quantum input/side channel, and no initially shared
   receiver/helper entanglement used to steer receiver state.
2. Before `F` or the execution is selected, fix a finite set `T` of **complete**
   helper transcripts, with `|T| <= D`. This is one support bound across all
   oracle tables and all executions. It is not the count seen in one run,
   the conditional support given each oracle, the payload length of one
   winning message, or a bound chosen after observing success.
3. The transcript contains all helper influence: payload values and lengths,
   identities/sources, order or fixed slot choices, release times visible
   to the receiver, absence, abort, errors, and any status/feedback the
   algorithm can use. A real-valued timestamp or an unrecorded scheduling
   choice can invalidate a finite alphabet. If signatures, source proofs,
   metadata, or their encodings are visible to the algorithm, their possible
   wire values must also be covered; it is insufficient to count only an
   extracted useful payload.
4. For each fixed `t in T`, forcing those classical responses gives a legal
   fresh-oracle receiver strategy `A_t`. The same hard total query bound `Q`
   and complete-output bound `M` hold on **every path of every `A_t`**, including
   counterfactual paths not encountered by the actual helper. An explicit
   clamp/refusal can enforce a bound in a hypothetical restricted model;
   an observed maximum alone cannot. The fresh tail bound `B` is uniform in
   `t`, as the frozen theorem permits arbitrary oracle-independent advice.
5. Helpers can preprocess or query `F` arbitrarily, but can influence the
   receiver only through this classical interface. Shared public data,
   verifier feedback, and cached results are also helpers for this purpose.
   Their influence cannot be omitted because their producers are honest.

These assumptions define a conditional theorem, not an attestation supplied
by a signed observation log. The observation validator checks that retained
deliveries fit a declared policy; it cannot prove that no other information
arrived or that the receiver lacked pre-existing oracle information.

An initial bounded **classical** advice string can be the first part of `T`
if, for each fixed string, the remaining receiver state is oracle-independent
or generated without further oracle information. This can account for that
specific form of preprocessing without pretending the advice is empty. It
does not cover an unbounded or unrecorded quantum residual state. If advice
is remembered across windows, its earlier transcript remains part of the
accounting; neither the oracle history nor `D` may be reset at a chosen
confirmation time.

### 4.2 Proof, including adaptive interactive helpers

Fix `t`. Expand the receiver's operation into its classical measurement/
request history while retaining all quantum state needed for each branch.
With `t` forced, the receiver's quantum operations and oracle queries on each
such branch are exactly those taken when the actual helper supplies `t`.
The actual interaction additionally multiplies the branch weight by the
conditional probabilities of the helper responses in `t`. Their product is
in `[0,1]`. Helpers may retain arbitrary private state, but the no-quantum-
coupling condition ensures it influences the receiver only through these
classical response probabilities.

Consequently, after summing over histories and the oracle distribution,

\[
\Pr[E\land T=t]\le\Pr[A_t\text{ succeeds}]\le B.
\]

This avoids conditioning the fresh oracle theorem on the event `T=t`, which
could substantially bias its oracle law. Sum over the one globally fixed
transcript set:

\[
\boxed{\Pr[E]\le\min\{1,D\,B\}.}
\tag{1}
\]

Receiver measurements and adaptive query choices are included. Helpers may
answer according to the receiver's classical requests: the forced response
strategy is still well-defined on each branch. Unmodeled quantum steering,
continuous timing, hidden inputs, or loss of the uniform counterfactual
budgets invalidates the premise; the proof is not extended to those cases.

For MU1 research credit use the already proved

\[
B=B_{\rm MU1}(Q,M,x),\qquad
N=2Q+M,\quad k=\lceil x/128\rceil,
\]

from [MANDATORY_UNITS_RELATION_V1.md](MANDATORY_UNITS_RELATION_V1.md).
In this application `Q` belongs to each forced-transcript strategy. Unknown
helper queries are covered by `D` only under the complete interface premise;
they are not falsely marked as measured or paid local queries. The formula
continues to concern the new MU1 credit, not native `required_work(target)`.

### 4.3 Executable complete-slot alphabet

[work_lifecycle_help.py](work_lifecycle_help.py) fixes an ordered sequence of at
most 64 slots. Slot `j` declares:

- `S_j` fixed source labels;
- `T_j` permitted delivery bins, with all finer timing unavailable to the
  algorithm as an additional premise;
- payload extent `0 <= length <= L_j` bytes;
- `E_j` error codes;
- one canonical absence outcome.

Data at each length can have every possible byte value. Thus an explicit
global alphabet upper bound is

\[
D_j=1+S_jT_j\left(E_j+\sum_{\ell=0}^{L_j}256^\ell\right),
\qquad D=\prod_jD_j.
\tag{2}
\]

Fixed slots remove an extra permutation factor; a different interface whose
arrival order carries information must include that information in its own
alphabet. Repeated or missing retained slots are refused, with absence
recorded explicitly. A zero-byte payload still carries information: absence
and empty data are distinct, as are sources, delivery bins, and errors.

The computation uses `Fraction` and caps the support count once `D B >= 1`,
without constructing an enormous `256^L` integer. This is exact upper-bound
saturation, not a numerical approximation to a useful tail. A separate
description-length upper bound is supplied for inspection. None of the
arithmetic functions certifies that its policy was fixed in advance or
completely mediated actual inputs.

### 4.4 Positive use and decisive negative controls

For the ideal-model choice `Q=1`, `M=64`, `x=8192`, the prior fresh bound is
about `0.0004604111154269779`. One slot with one fixed source, one delivery
bin, at most one payload byte, and no error code has
`D=1+(1+256)=258`. Equation (1) is then about `0.1187860677801603`, below one.
This is a nontrivial conditional example, not an actual chain risk estimate.

The real imported `u=2` packet is 98,882 bytes. Even the hypothetical bounded
slot used for that import has an enormous alphabet; the same formula returns
one. Signing its source reference does not reduce that information cost.
The fact that only one such packet was observed does not justify `D=1`.

An exact counterexample demonstrates the distinction. In an eight-address
Bernoulli table with `p=1/16`, a helper with arbitrary preprocessing returns
the first marked address, or address zero if no address is marked. For each
fixed oracle the reply is deterministic, so its oracle-conditioned support
has size one. Across all oracles it can return all eight addresses. A receiver
making zero new queries succeeds with

\[
1-(1-p)^8>p.
\]

Using `D=1` with the fixed-address fresh bound `p` is false. Using the global
support `D=8` gives the valid upper bound `8p`. The tests independently
enumerate all 256 oracle tables with exact rational probabilities. Another
enumeration checks an adaptive one-query interaction against both forced
classical response strategies. These controls validate the scope distinction;
they do not prove the quantum theorem by simulation.

## 5. Authentic observation and eligibility are separate outputs

The collection verifier can report true for:

- actual ML-DSA verification against the supplied external pins;
- complete retention of the declared anchored event fragment;
- actual W1 and MU1 artifact predicates recomputed from retained bytes;
- recursive matching of signed source endpoints and published artifacts;
- recorded deliveries fitting the declared finite policy.

It always reports false or null for:

- genuine independent trust-root establishment or recorder execution
  attestation;
- all-world event coverage and a lifecycle query upper bound;
- initial oracle independence or a joint residual-state certificate;
- complete mediation/global support of public help;
- actual SHA-256's preprocessing-aware ideal-oracle composition;
- physical resource-to-credit tails, native confirmation risk, or production
  qualification.

`query_budget_from_observation` has no supported promotion path. It refuses
even a dictionary claiming that all those flags are true. `finite_help_weight_bound`
is a separately named conditional theorem calculation; it does not consume
an authenticated log and silently turn observation counts into `QueryBudget`.

## 6. Reproducible actual execution and retained evidence

The observer [work_lifecycle_observe.py](work_lifecycle_observe.py) requires the
existing built `pon_work_io` and `pq_message_oracle`. It executes five real
W1 verifier calls on actual full-size units: four successful validations and
one deliberately invalid trace rejection. It generates two temporary random
ML-DSA-65 keys, signs four endpoints, verifies the linked collections, and
uses the actual RustCrypto example to check four valid OpenSSL signatures
plus eight changed-message/zero-signature controls in one process exchange.

The source and receiver records import the frozen prior MU1 packet rather
than silently pretending it was generated during this new lifecycle. Public
receipt recomputation performs zero native calls; separate calls test the
real verifier's behavior. The hash-composition record includes the exact
terminal SHA-256 input frame.

The Python dependency must actually expose ML-DSA-65 generation, pure signing,
verification, and DER public-key serialization; absence is an explicit error,
not a fallback. The installed runtime versions are written into the evidence.
An API-availability test does not claim a different CI dependency version
was executed; the CI environment must run its own exact-version checks.

From the repository root, after building both existing release examples:

```bash
WLC_NATIVE_WORK="$CARGO_TARGET_DIR/release/examples/pon_work_io" \
WLC_NATIVE_PQ="$CARGO_TARGET_DIR/release/examples/pq_message_oracle" \
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p work_lifecycle_tests.py -v
```

The suite requires both native paths. A missing binary is a test failure.
It is separate from the durable evidence command:

```bash
python3 formal/pon-nakamoto-v1/work_lifecycle_observe.py \
  --native-work "$CARGO_TARGET_DIR/release/examples/pon_work_io" \
  --native-pq "$CARGO_TARGET_DIR/release/examples/pq_message_oracle" \
  --out "$TRNM_CI_RECEIPT_DIR/work-lifecycle"
```

Use a new output directory. Exclusive creation prevents overwriting old
observations. Native-call artifacts and a JSONL journal are persisted as
exchanges occur, so later failure preserves already observed calls. Outputs
include signed source/receiver ledgers, separately supplied public endpoint
pins, retained public input/output artifacts, the unkeyed-receipt control,
actual hash composition, native PQ differential records, conditional help
calculations, exact source/binary digests, runtime versions, and all unchanged
qualification flags. Secret signing material is not written.

Elapsed readings are observations of these runs. They are not minimum costs,
physical-clock attestations, or a proof that a concurrent helper did no other
work. Repeated validation of already produced work does not count as newly
created work for an adversarial resource bound.

## 7. What this closes and what remains

| Obligation component | Result |
| --- | --- |
| Exact actual MU1 terminal-hash composition | Reconstructed and checked against full-size frozen work |
| Existing unkeyed receipt as execution attestation | Concrete counterexample; unsupported interpretation rejected |
| Tamper-resistant observation/source fragment under pinned keys/endpoints | Defined, implemented with actual ML-DSA-65, and independently verified by RustCrypto |
| Complete source-reference checking and artifact relation replay | Recursive signatures, endpoint binding, published-byte binding, full W1/MU1 checks |
| Limited public-help reduction | Full proof of `min(1,D B)` under a globally fixed complete classical interface and uniform forced-strategy budgets |
| An actual full-lifecycle query upper bound | Still absent; local observation does not exclude hidden work or advice |
| A real initial-state or residual-state certificate | Still absent |
| Actual SHA-256 preprocessing-aware oracle reduction | Still absent |
| All-algorithm minimum actual work cost | Still absent; no replacement of W1 by a cheaper model |
| Native identity/weight/event-clock bridge and six-successor risk | Not supplied by this observation or help theorem |

This is concrete progress in provenance, refusal boundaries, and one bounded
information-channel reduction. The first scientific obligation remains open
at actual resource completeness/minimum cost and initial-state qualification.
The second still requires the independent native event mapping and its actual
network, time, availability, inventory, identity, and weight certificates.

## 8. Primary sources and relation to earlier work

ML-DSA is specified by
[NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).
The implementation uses the installed public API documented by
[cryptography's ML-DSA signing reference](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/mldsa/)
and cross-checks against the repository's existing RustCrypto verifier.
The algorithm standard does not establish this observer's key custody,
physical execution, independent administration, or resource coverage.

Carolan, Poremba, and Zhandry's primary research,
[(Quantum) Indifferentiability and Pre-Computation, IACR ePrint 2024/1727](https://eprint.iacr.org/2024/1727),
shows that ordinary indifferentiability is generically insufficient for
precomputation security and proposes a stronger notion. Its one-round sponge
application is not a theorem about this repository's concrete SHA-256/MU1
construction. This supports retaining the preprocessing-aware composition
gate; it does not fill it. The finite-help argument above is proved here and
does not import constants or a SHA-256 reduction from that paper.

The frozen [MU1 query proof](MANDATORY_UNITS_RELATION_V1.md) and
[stateful resource interface](STATEFUL_RESOURCE_TAIL_V1.md) remain unchanged.
WLC1 does not convert their assumptions into facts by recording or signing
them.
