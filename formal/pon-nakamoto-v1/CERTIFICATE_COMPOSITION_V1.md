# CC1: exact evidence joins without probability or resource promotion

## 1. Result and scope

CC1 combines two independently useful kinds of evidence: a durable local
native-owner journal, and ML-DSA-65 signed observation fragments with retained
artifacts. Its positive result is an **exact byte-level join**. A particular
signed publication refers to the same packet bytes as a particular local
native census row. Native block identities are counted once across repeated
publications. Open intervals, crash gaps, validation-clock regressions and
orphan artifacts remain visible in the combined result.

This join does not make a signing key into a physical query meter. It does not
equate a native PNP1 block's required work with the research PMU1 relation's
credit. It does not certify the world's ready inventory, an initially fresh
joint quantum state, the complete visible helper transcript, an authenticated
network clock, or a six-successor failure probability. These are separate
logical implications, not fields a caller may turn on.

The implementation is `certificate_composition.py`. The required evidence
driver is `certificate_composition_evidence.py`; its input is the original
`native_owner_journal_v1` scenario's `run.json` together with all referenced
binary journals and native packet files. It cannot accept a caller-created
`Verified` object instead. `certificate_composition_tests.py` checks the exact
model counterexamples and real cryptographic attribution control.

The starting source anchor is commit
`88bce414d7ba7f7f6a60dba03943ee20dc501ed7`. This identifies the previous source
state. New files are bound by the evidence run's exact source manifest, not by
an assertion that they already existed in that commit. The executable driver
samples source and input hashes before and after checking and refuses changed
inputs; those samples are not execution attestation.

## 2. What the raw-source join checks

For each native journal, the mandatory `native_owner_journal.read_journal`
reader checks the original PNOJ1 frames, lengths, sequence, predecessor hashes,
context, state transitions and supplied prefix expectation. It reads the
packet files by exact SHA-256, parses their native wire representation,
recomputes native block IDs, proof hashes, transaction roots and required
work, and checks correspondence with the complete local census rows. The
reader reconstructs strict local fork inequalities and transaction membership
from the retained observations.

The Python reader does **not** independently repeat the native application's
full W1 and state-transition replay. Full native replay is performed by the
actual Rust census when the journal is produced. A serializable census is a
record of that execution, not an independently authenticated execution proof.
The join therefore preserves `native_census_claims_complete_relation_replay`,
`python_replays_full_work_relation=false` and
`execution_independently_attested=false` from each binding. It does not change
their meaning by wrapping them in a second signature.

For the signed side, `work_lifecycle_certificate.verify_collection` verifies
actual ML-DSA-65 signatures against separately supplied public-key and
endpoint expectations. It checks the complete anchored fragment, recursive
source references and artifact hashes. Whenever that fragment contains a W1
or PMU1 predicate claim, the existing verifier recomputes the complete
predicate. A public-key pin supplied by this test is an expectation used by
the verifier; the test does not certify independent external retention of the
pin or the signer's physical identity.

A join is accepted only when all of the following refer to the same bytes:

1. The exact signed export event names packet SHA-256 `h`.
2. The artifact store contains raw bytes with SHA-256 `h`.
3. The journal's `valid_packet_bindings[h]` comes from an exact packet present
   in a complete local census, rather than from a raw `admit` input alone.
4. That binding's recomputed native block ID matches the requested ID and its
   512-bit required-work value has the expected native encoding.

The evidence driver signs both an actual valid packet and an actually refused
packet whose corrupted proof has the **same native block ID**. The valid
publication joins successfully. The invalid publication has a valid signature
and a matching header ID but fails with
`EXACT_SIGNED_PACKET_NOT_NATIVE_VALIDATED`. This distinguishes exact predicate
provenance from a header-ID lookup. Two references to the accepted publication
produce one distinct native identity and one required-work contribution.

PNP1 bytes are published under the existing WLC `classical_help` artifact role
in this control. That role asserts possession/publication of bytes; it does
not assert that a PNP1 packet is a PMU1 packet. Their native semantics are
joined through the raw journal separately.

## 3. Restart, reorganization and recovery cannot reset origin

The durable owner wrapper holds its `Node` exclusively and exposes no raw
node reference or callback. It records and synchronizes an intent before the
native business operation. Completion requires the native result, a complete
post-operation census, packet artifacts, a terminal frame and its successful
durable write. The separate sidecar is not a transaction shared with the
native database.

The independent composition scenario checks three distinct histories:

* **Unadmitted output across restart.** A complete A8 packet is produced and
  retained before a clean owner close, then admitted after reopen. Its first
  registry origin remains `recorded_local_production` in epoch 1. Subsequent
  native validity may be established by census, but a later admission does
  not change the first source or turn it into freshly generated work.
* **Native commit followed by process exit.** A real child performs native
  activation successfully and exits before its terminal journal observation.
  Recovery can show the new selected chain. The old prepared activation
  intent remains unresolved, and an outside-lease interval remains present.
  Seeing the expected recovered state does not repair the missing observation
  or attest the intervening work, clock or inventory.
* **An internally consistent old snapshot.** An actual earlier database and
  sidecar prefix can still be parsed without a newer external expectation.
  The recovered newer checkpoint rejects that old prefix. Without the newer
  expectation, parseability grants neither authenticated history nor fresh
  initial resource state. No hash chain alone establishes which prefix is
  the latest physical history.

Strict native rollback witnesses partition the competing suffix by the
recorded first local source. Reorganization does not rewind journal sequence
or the source registry. That partition is explicitly not the global
adversarial/honest/initial-ready partition needed by a security theorem.

Artifact files can be durably written before their referencing frame. The
journal's bounded directory scan exposes such orphans rather than treating a
restart as an empty inventory. CC1 passes orphan observations and unreferenced
artifacts through without granting them effective work or fresh-generation
credit. Missing volatile or remote artifacts are still outside this local
claim.

Validation `observed_now` is caller supplied. A per-process monotone `Instant`
does not authenticate global wall time or order separate epochs. The fixture
deliberately moves the validation clock across a future ancestor and then
back. The journal records the regressions; CC1 cannot spend them as a
propagation-delay or work-rate bound. Likewise, a complete census covers
current locally admitted rows at its consistent snapshot. It does not cover
remote branches or all private ready packets.

## 4. A real signature and a valid proof do not prove production

The attribution negative control starts from actual retained W1 verifier
input in the previous evidence corpus. It hashes the raw artifact and
recomputes the full W1 predicate. From those already valid bytes it extracts
the old proof and its original producer input.

The control generates a real ML-DSA-65 key and signs a `native_call` event
claiming that the native producer was just called with that input and returned
the proof with exit status zero. It also signs publication of the proof. The
construction makes **zero native producer invocations**. The subsequent WLC
verifier accepts the actual signature and recomputes the valid complete W1
predicate. Its `reported_native_calls=1` is therefore a count of a signed
statement, not an independently measured program invocation. A subprocess
guard makes any accidental native producer launch fail the control.

This example does perform verification work. It makes no claim that the proof
was never produced, that verifying W1 is free, or that a valid signature can
be forged. It demonstrates a narrower failure: possession of old valid
bytes, a signing key and a correct program hash suffices to make a signed
execution statement that is false. Replacing the statement's signature with
corrupted signature bytes is separately rejected by the actual verifier.

Consequently, exact signature and predicate checks cannot establish first
ready time, freshly performed work, the producer's physical identity, complete
query mediation or an absence of preprocessing. WLC's query-budget promotion
continues to refuse with
`LIFECYCLE_COVERAGE_AND_INITIAL_STATE_UNATTESTED`.

## 5. Global prior risk is not conditional risk at a selected start

The LQC model uses one fixed ideal terminal oracle and one coalition lifetime.
Its two interfaces have different probability scopes:

| Interface | Meaning |
| --- | --- |
| `global_lifecycle_weight_bound` | Unconditional law from an independent joint initial state, averaging the complete paid classical prefix |
| `continuation_given_complete_prefix` | Conditional law after the actual complete coalition prefix, retaining the actual distinct-address and known-winner counts |

CC1 reconstructs the entire returned report from its parameters, including
exact rational arithmetic, field set and qualification flags. Merely editing
`probability_scope`, a bound or a flag is rejected. Every non-root use in its
finite probability-tree checker requires the conditional interface. It then
computes the actual conditional event ratio from the **same complete declared
joint law**, rather than trusting the interface label or supplied prefix
counts as facts about that law.

Here is a paid-prefix counterexample that needs no unaccounted query. Let
`p=1/16`, `C=1`, `Q=0`, `M=1`, and ask for one identity (use the relaxed
128-credit ceiling). Reveal one address; if it loses, output a different
unqueried address. The global success probability is

\[
 p+(1-p)p=31/256.
\]

At the observed prefix where the first revealed address won, the conditional
success probability is one. Reusing `31/256` there is false despite having
paid for the prefix query. Correct continuation retains `s=1` and returns
one. If a caller supplies a mathematically valid `s=0` report at that same
history, the finite-law checker rejects its conditional risk claim.

For repeated uses, let each start event be a history cell, with allowance
`a_j` fixed at that cell and actual conditional failure probability at most
`a_j`. If every complete history pays

\[
 \sum_{j:\,\text{start }j\text{ occurs}} a_j\le\alpha,
\]

then the original-law union bound gives

\[
 \Pr(\text{some failure})
 \le \sum_j \Pr(\text{start }j)a_j
 \le \alpha.
\]

No independence between failures or starts is required. All occurrences of
an allowance must actually be paid. In the two-address example, two attempts
of risk `p` have union probability `31/256>p`; spending one shared `p` twice
is refused, while a path budget `2p` is valid. This checker certifies the
declared finite probability tree only. It does not authenticate an actual
network probability law or the joint initial state at a native confirmation.

## 6. A later classical reveal cannot start a fresh prefix after quantum work

Consider an ideal Bernoulli oracle on 16 addresses. Start in the uniform
superposition, make one phase query and apply the usual reflection about the
uniform state. If the table has `m` marked entries, each marked amplitude is
`(3-4m/16)/4`. Measuring an address and then classically revealing its mark has
conditional success probability

\[
 (m/16)(3-4m/16)^2.
\]

Averaging over `m~Bin(16,1/16)` gives exactly

\[
 13073/32768 > 1/16.
\]

CC1 computes all 17 mark-count cases as exact rationals and checks amplitude
normalization for each. This is a finite mathematical calculation, not a
quantum hardware experiment. It disproves treating that later classical
reveal as a new independent Bernoulli prefix trial. A new process, signer,
helper label or local owner does not reset the coalition's first coherent
query boundary. Every subsequent classical feedback query belongs to the
post-prefix accounting unless a separate valid theorem explicitly covers it.

## 7. Complete observable help includes timing

A helper queries 16 independent addresses and, if any wins, sends the same
empty payload in the arrival bin naming a winning address. If all lose it
uses bin zero. The receiver reads the arrival bin and outputs that address,
with no receiver query. Its success probability is

\[
 1-(15/16)^{16}
 =11878335717996660991/18446744073709551616.
\]

There is one payload value but 16 informative delivery times. A complete
one-slot WLC policy covering these bins and absence has support 17. A coarse
recorder can place every delivery in its own bin zero and validate its own
record while the receiver still observes the finer clock. Record-policy fit
therefore does not certify complete mediation of observable help.

This exact model exceeds the unpaid-helper fresh bound `1/16`; it also
exceeds the older conservative fixed-output bound `529/1024`. Finite-help
theorems require an a priori alphabet for the whole visible transcript,
including timing, length, source, order, absence and errors, plus their stated
joint-state and counterfactual-budget conditions. Counting payload hashes
observed in one run cannot replace that hypothesis. CC1 does not claim a
physical covert-channel experiment.

## 8. Remaining implications that no local join supplies

The LQC weight event counts unique valid MU1 identities in a declared complete
output history. To use it for private completed or ancestor-ready inventory,
one must supply an oracle-free extraction of the complete candidate list and
a hard `M` that covers **all** extracted inventory on every path. A local
`emit` count, an owner census and a signed publication list do not establish
that premise. The dedicated flag
`hidden_inventory_output_extraction_and_cap_attested` remains false.

Likewise, native PNP1 acceptance is not an enforcement of the PMU1 aggregate
lottery or its `16u` credit rule. A sound bridge would have to map every
relevant native competing-weight contribution to distinct terminal inputs,
prove a compatible maximum identity credit and preserve all challenge,
selection, inventory and ancestry conditions. A shared W1 subroutine, a
common signer, or equal numbers in a toy run do not prove that bridge.

Even after such a relation bridge, the query tail would still require a
closed coalition lifecycle with an authenticated joint initial-state or
residual-state assumption and complete treatment of public help. Native
failure witnesses would still require their stated availability,
selection-lag, timestamp, weight-cap and propagation envelopes under the
same probability law. Local debt-free observation alone supplies none of
those physical or probabilistic assumptions.

`native_risk_from_join` therefore rejects every attempted native-risk
promotion with
`NATIVE_RELATION_RESOURCE_STATE_AND_WORLD_BRIDGES_UNPROVED`.
Successful local checks retain `production_qualified=false` and a null
native six-successor failure probability.

## 9. Reproduction and retained failures

Run the independent finite-model and real-signature controls from the
repository root:

```sh
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p certificate_composition_tests.py -v
```

The retained real W1 input is mandatory; a missing input, missing ML-DSA-65
implementation, invalid signature or failed full predicate stops the test.
There is no fake proof, fallback signer or skipped native stand-in.

After the actual native journal scenario has finished and its original
packet directories are available, run:

```sh
python3 formal/pon-nakamoto-v1/certificate_composition_evidence.py \
  --native-run /absolute/path/to/native-scenario/run.json \
  --output-dir /absolute/path/to/new-composition-attempt
```

The output directory must be new. The driver retains public signatures,
public endpoint expectations, exact signed artifact bytes, all reader
results, negative controls, source hashes and exact rational calculations.
On failure it retains the completed stages and a failed attempt record.
Native producer binaries are not invoked by this composition program;
native execution is exercised by the separately retained actual scenario.
Its PASS means those concrete checks succeeded, not that either scientific
security obligation has been promoted to an unconditional native theorem.
