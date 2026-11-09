# W1 lifetime accounting and three independent acceptance lines

Status: **conditional arithmetic and selected implementation observations;
security HOLD**. This continues the
[single development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and the [fixed W1 implementation map](W1_QROM_IMPLEMENTATION_MAP_20261107.md).
It does not change a consensus rule, deployed limit, signed domain, verifier,
proof parameter, or existing acceptance contract.

The original 2026-11-07 report below remains historical evidence with its
original bytes. The [2026-11-09 successor](../../evidence/pon-w1-lifetime-current-20261109/README.md)
binds the current ledger's 20 selected inputs to exact source
`189b9b5959d836ef6ae96e14fb285948e4920aa9`; the child containing that ledger is
separate from this selected-source base. The successor retains the same 19
named controls, unknown lifetime input and security HOLD. It does not replace
the original report or the fixed historical source-observation profile.

The original [ledger](../../scripts/w1_lifetime_ledger.py) and
[19 controls](../../scripts/ci/test_w1_lifetime_ledger.py) make several obligations
executable. They reproduce exact integer/rational accounting, refuse omitted
budget classes and invalid extrapolation, and bind observations to 20 selected
source files at base commit
`7150d96a2112875b4afcf3023361a5cef4a0e4b1`.
They do not prove that an adversary obeys a supplied bound, instantiate QROM,
verify a signature or receipt, or run a quantum device.

The actual project input leaves all lifetime counts and error bounds unknown.
Its [reproducible report](../../evidence/pon-w1-lifetime-20261107/project-report.json)
therefore returns null for total adversary queries, the project error bound and
the project target comparison. Each of the three security qualifications remains
false. These outcomes are calculated independently of historical qualification
labels; changing a stored HOLD string cannot supply missing cryptographic proof.

## 1. One lifetime envelope, including unsuccessful work

The input has one horizon and one aggregate processor envelope. It requires
that preprocessing before deployment, all identities, delegation, reorganizations
and protocol upgrades share the declared accounting scope. Changing any of
these requirements or replacing the query unit with a native permutation count
is refused.

An online duration is a declared horizon, **not a conversion factor from seconds
to quantum queries**. Every count below must already bound the whole declared
lifetime, including relevant earlier preprocessing. A processor count is also
a premise, not an inference from observed hosts or a per-peer admission limit.

| Phase | Occurrences charged over all processors | Queries additionally needed |
|---|---|---|
| Offline preprocessing | Processor maximum times lifetime preprocessing batches per processor | Bound per batch for every relevant primitive interface |
| Accepted root attempts | Processor maximum times accepted root attempts per processor | Complete root-attempt query bound |
| Failed or abandoned roots | Processor maximum times failed, aborted and retried root attempts per processor | Bound that includes work before rejection or abandonment |
| Recursive subproof nodes | Processor maximum times **accepted plus failed** roots times additional recursive nodes per root | Bound per internal node |
| Adaptive restart batches | Processor maximum times additional adaptive/restart batches per processor | Extra queries not safely covered by a smaller envelope |
| Delegated service batches | Processor maximum times declared service/delegation batches per processor | Relevant queries obtained through other actors or services |
| Cross-protocol/unclassified batches | Processor maximum times remaining batches per processor | Unknown uses remain unknown |

These are upper envelopes. Phases may overlap conservatively; they must not be
silently deduplicated or charged only for winners. Let \(P\) bound processors,
\(A,F\) accepted and failed root attempts per processor, and \(R\) additional
recursive nodes per root. Then the declared internal-node envelope is

\[
N_{\mathrm{recursive}} \le P(A+F)R.
\]

For each accounting group \(g\), if \(N_h\) bounds phase occurrences and
\(c_{g,h}\) bounds its queries per occurrence, the ledger computes

\[
Q_g^{\mathrm{adv}} \le \sum_h N_h c_{g,h}.
\]

For example, three processors, two accepted and five failed roots per
processor, seven internal nodes per root, and eleven queries per node produce
an internal-node query envelope of \(3(2+5)7\cdot11=1617\).
Dropping the five failed roots changes the result and is not authorized by an
accepted-receipt count.

Every required field must be present. Null is the representation of unknown;
even a known zero times an unknown remains unknown in this conservative
auditor. Explicit numerical premises need a nonempty provenance reference,
but the reference is labelled **unverified** and cannot itself certify a bound.
Booleans, floating-point values, negative counts, duplicate JSON keys, additional
fields and noncanonical decimal strings are rejected.

The ordinary Node does enforce local CPU and signature budgets. In
[prepare_signature_metered](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2.rs),
the shared counter is charged before `verify_tpq1`; a failed verification is
not refunded. That controls a particular owner's service cost. It places no
limit on an adversary's independent offline or quantum computation.

## 2. Hash-purpose groups are selected coverage

The fixed roster is **selected implementation coverage, not a proof of
exhaustiveness**. Its `other_unmapped` row is mandatory and initially unknown.
Supplying a number, including zero, does not turn
`coverage_exhaustiveness_proved` into true.

| Accounting group | Selected actual uses | Evidence and remaining model boundary |
|---|---|---|
| Shared Poseidon2 | STARK leaves/nodes, control-tree internal nodes, transcript message hashes and stateful RNG | Existing pinned [FRI/transcript source map](../../scripts/w1_fri_transcript_audit.py). These uses share the suite; a purpose label does not create independent random oracles. |
| Shared SHA-256 | Native challenge/task/noise/ticket, ordered arithmetic transcript, work/artifact/journal identities, zkVM claim/parameter commitments, TPQ1 key identity | [Native W1](../../trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs), [TPQ1](../../trillionnium/crates/trnm-protocol/src/pq_frame.rs), and [implementation map](W1_QROM_IMPLEMENTATION_MAP_20261107.md). Different roles need different properties; no blanket quantum-bit assignment is made. |
| Shared SHA-384 | TPQ1 payload commitment | Explicit domain, payload tag and big-endian length in `payload_commitment`. Wider payload hashing does not migrate the SHA-256 key ID or W1 ticket. |
| Shared SHA-512 | Crypto profile configuration ID and separate candidate commitments | [Profile source](../../trillionnium/crates/trnm-protocol/src/crypto_profile.rs). Candidate choices do not automatically replace existing native owners. |
| ML-DSA XOF boundary | Internal signature XOF use | The exact [Cargo lock](../../trillionnium/Cargo.lock) pins `ml-dsa 0.1.1` and its `shake` dependency. This survey does not expand or idealize every dependency invocation. |
| Other/unmapped | Remaining application, authorization and protocol uses | Open. This group prevents a fixed partial roster from masquerading as a whole-system inventory. |

One coherent query may address several purpose tags or interfaces in
superposition. The group sums are conservative caller-premised envelopes,
not measurements of a disjoint partition of quantum queries. No independence
or domain-separation theorem is inferred. The mapping from concrete hash,
compression, sponge or permutation calls to an abstract oracle invocation still
requires proof; forward/inverse access and coherent simulation must be specified
there.

For the same reason:

- Fifty FRI query openings are protocol parameters, not adversary query counts.
- Thirty-two RNG permutations in the saved seal's source geometry do not bound
  transcript searches, Merkle construction, nested proofs or unsuccessful runs.
- A digest stored in 32 bytes does not automatically instantiate a uniform
  256-bit random oracle.
- Sharing code across different roles does not give the independent-oracle
  assumption needed by some proofs.

The ledger separately retains Fiat-Shamir online mass and commitment online
mass. It refuses mass larger than a fully known declared adversary envelope,
but does not set either mass equal to the query count or impose an unproved
identity between them. Extractor, committed-relation-decider and simulator
query overheads are also separate unknowns. Their additive bookkeeping is
**not** a substitution for CDHZ's actual shifted budgets and composition terms.
Every group reports `mapped_to_cdhz_t_or_w=false`.

## 3. A lifetime union calculation needs the right event bound

There are three named opportunity classes: authorization admission,
complete-relation verification, and work/weight acceptance. A usable input must
bound opportunities including rejected attempts; the complete-relation count
cannot be smaller than the declared accepted-plus-failed root envelope.
Additional application opportunities need their own conservative counts.

If, for every admissible prior history and adversarial quantum auxiliary state,
the \(i\)-th opportunity has conditional failure probability at most
\(\epsilon_i\), and the claimed envelope covers all such opportunities, then

\[
\Pr[\text{some failure}] \le
\min\!\left(1,\sum_i \epsilon_i\right).
\]

For at most \(n_j\) opportunities of each class with a uniform conditional bound
\(\epsilon_j\), the displayed expression becomes
\(\min(1,\sum_j n_j\epsilon_j)\).
This arithmetic needs no independence. Establishing the uniformly valid
conditional bounds is the hard premise. A bound must include the relevant
offline information, adaptive choices, auxiliary states and the **same
lifetime query envelope**.

Each supplied error also declares the largest joint-query envelope for which
it is assumed valid. A smaller domain is refused when the ledger's declared
queries, including additional reduction queries, exceed it. Unknown domain,
mass, overhead or lifetime values prevent a hypothetical target comparison.
The reader does not extrapolate an error derived for \(q\) to a larger \(q'\),
nor convert a conjectural classical FRI estimate into an RBR knowledge bound.

The three event errors are assumed **complete event bounds**, not independently
summed CDHZ component constants. A full QROM/composition theorem must first
supply the computation-relation event bound. Merkle correctness,
commutativity, offline extractability and online indistinguishability cannot
be inserted as four new whole-proof failure probabilities by this reader.

Even with every number filled in, only an input explicitly marked
`hypothetical` can produce `hypothetical_expression_meets_target=true`.
`project_total_error_upper` and `project_target_met` remain null,
`uniform_conditional_premises_verified` remains false, and no acceptance
line becomes qualified.

### Executable counterexamples

The [counterexample output](../../evidence/pon-w1-lifetime-20261107/counterexamples.json)
contains exact fractions:

1. **Budget reset:** two batches of ten queries give \(Q^3=8000\);
   adding two separately reset cubic terms gives \(10^3+10^3=2000\).
   The factor-four discrepancy is an arithmetic example, not a concrete
   attack or a claimed CDHZ bound.
2. **Adaptive selection:** let \(R\) be uniform on sixteen values and statement
   \(x\) fail exactly when \(x=R\). Every fixed \(x\) fails with probability
   \(1/16\); after the history reveals \(R\), selecting \(x=R\) fails with
   probability one. A marginal fixed-statement bound is therefore insufficient.
3. **Per-event versus whole-life target:** sixty-four opportunities each
   bounded by \(2^{-128}\) give union expression \(2^{-122}\), which does not
   meet a \(2^{-128}\) total target. These are hypothetical errors, not measured
   project security bits.

## 4. Three independent acceptance lines

The report binds every source observation to its path, SHA-256 and an anchor
line. It confirms the bytes surveyed, not a whole-repository build, fresh
cryptographic execution, key custody or a deployed effect. Existing labels are
not used as evidence that a mathematical obligation has been proved.

| Line | Actual selected source observations | What remains independent |
|---|---|---|
| PQ authorization | [pq_auth.rs](../../trillionnium/crates/trnm-crypto-primitives/src/pq_auth.rs) uses the exact RustCrypto `MlDsa65` message verifier. The locked crate is `ml-dsa 0.1.1`; canonical SPKI is 1,974 bytes, raw key 1,952 bytes and signature 3,309 bytes. Optional OpenSSL is a signing/differential source whose signatures still pass the canonical verifier. The application resolves current authority and charges attempts before TPQ1 verification. | Primitive/implementation assumptions, full authority-entry coverage, owner pins and custody, migration, revocation/replay/rollback and the lifetime multi-user authorization bound. A signature observation alone grants no balance, nonce, release or FinalUse authority. |
| Complete computation relation | [WorkCheckedPacket::verify](../../trillionnium/crates/trnm-pon-node/src/store.rs) calls the native full PNW1 verifier. [NPQ6 packet checks](../../trillionnium/crates/trnm-pon-node/src/pq_application_v6.rs) retain `pon_work::PROOF_BYTES`. The [isolated hardened succinct verifier](../../formal/pon-nakamoto-v1/w1_hardened_verifier/src/main.rs) is a separate path. | Native replay correctness and succinct-proof QROM soundness are different claims. Full implemented relations, compiler/guest mapping, all recursive programs, RBR/state-restoration, actual commitments/transcript and lifetime composition remain separate obligations. This survey does not rerun the receipt verifier. |
| Quantum work and chain weight | [PreparedTask](../../trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs) retains public product material for legal reuse. A [full fixed-template reversible winner construction](../../formal/pon-nakamoto-v1/w1_quantum_oracle.py) and a [prefix-restricted legal strategy](../../formal/pon-nakamoto-v1/w1_quantum_restricted_oracle.py) already exist. The [resource model](../../formal/pon-nakamoto-v1/quantum_oracle_resources.py) charges compute/inverse, all processors, and candidate checks after failed completed trials; the [clock](../../formal/pon-nakamoto-v1/quantum_resource_clock.py) has explicit physical premises. | A constructive circuit supplies an algorithmic upper bound, not the cheapest attacker lower bound. A restricted strategy must use its own marked count. Task/parent eligibility, alternative strategies/reuse, physical calibration, actual branch reachability and the chosen confirmation/security definition still need evidence. |

FIPS 204 specifies ML-DSA for digital signatures; it does not certify these
application ownership rules, the STARK, or the work lottery.
The [NIST publication page](https://csrc.nist.gov/pubs/fips/204/final) also carries
a 2026-07-31 errata planning note. Source pinning and successful conformance
tests do not establish an independent implementation or side-channel audit.

## 5. What chain weight does, and what it does not establish

The current [consensus source](../../trillionnium/crates/trnm-pon-node/src/consensus.rs)
defines

\[
W(T)=\left\lfloor\frac{2^{256}}{T+1}\right\rfloor.
\]

The [store](../../trillionnium/crates/trnm-pon-node/src/store.rs) adds this
quantity to the parent's checked 512-bit work. This is actual integer weight;
it is not a measurement of energy, Toffoli gates, quantum time or the cost of
the cheapest legal producer.

Under an **ideal uniform ticket** and a target chosen before a distinct first
classical ticket query, the hit probability is
\(p(T)=(T+1)/2^{256}\), so expected credit is
\(p(T)W(T)\le1\).
The existing [classical query accounting](../../formal/pon-nakamoto-v1/work_query_bound.py)
states its precise conditional assumptions. The new tests exhaust small
domains to check the rounding identity. That finite arithmetic is neither a
quantum query theorem nor a common-prefix or finality proof.

The [development configuration](../../config/pon/devnet-v1.json) fixes
sixteen-block periodic retargeting and ten-second spacing: desired span
150 seconds, integer lower clamp 38 and upper clamp 600, median eleven, and
120-second future allowance. The actual selected rule is not ASERT.
The separate [DAA model](../../formal/pon-nakamoto-v1/quantum_daa_model.py)
chooses square-root cost scaling explicitly; its `.sqrt()` is a premise.

The fourth executable counterexample uses targets \(2^{248}-1\) and
\(2^{244}-1\), whose weights are 256 and 4096. If full-oracle search cost
increases only fourfold, weight per unit cost increases fourfold. It assumes
equal oracle cost and square-root search scaling; it does not demonstrate that
an attacker can reach or sustain those targets under this Node's DAA.

[Bailey and Sattath, arXiv:2403.08023v2](https://arxiv.org/abs/2403.08023v2)
analyze this weight-versus-search mechanism in Bitcoin-style settings.
[Zalka's black-box search result](https://arxiv.org/abs/quant-ph/9711070v2)
is a query-model result, not a calibrated W1 hardware clock. Neither is
automatically a complete attack or security proof for this Chain.

## 6. Reproduce and interpret the result

Run from the repository root:

```sh
bash scripts/project-preflight.sh
python3 scripts/w1_lifetime_ledger.py --template > /tmp/w1-lifetime-input.json
python3 scripts/w1_lifetime_ledger.py --input /tmp/w1-lifetime-input.json
python3 -m unittest discover -s scripts/ci -p 'test_w1_lifetime_ledger.py' -v
```

The report is deterministic for the same source and input. JSON integers and
fraction numerators/denominators are serialized as decimal strings to preserve
large values through consumers. Report exit zero means accounting/source
survey completed; malformed input or source drift returns exit two and a
`REFUSED` error. Neither exit code is cryptographic acceptance.

The retained [observation](../../evidence/pon-w1-lifetime-20261107/observation.json)
records the real commands, outputs, source baseline and script/report hashes.
The nineteen tests cover missing phases, budget resets, unknown propagation,
failed-root recursion, all-processor accounting, query-domain extrapolation,
mass/overhead separation, exact union and lottery arithmetic, source drift,
symlink substitution, malformed JSON and unsupported qualification fields.

No Rust source or upstream proof source is executed by the reader. No runtime
signature, STARK verification, fresh native admission, independent quantum
hardware or production deployment is claimed by this evidence.

The three conclusions remain separate:

> PQ signatures protect authorization; complete proofs protect a specified
> computation relation; quantum-work analysis protects the correspondence
> between resources and chain weight.
