# Joint lifetime obligation review and conditional root composition V2

Status: **research only; HOLD / NO-GO**. The actual lifetime failure bound is
still unknown. This change checks the relationship between two reviewed source
inventories and implements conditional probability arithmetic. It does not
prove a complete security experiment, a concrete cryptographic reduction, an
adversary resource budget, or production qualification.

The review baseline is [PR #837](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/837)
at [44330b91eb552fd20ef6f2e69bf5e6f1e8f5c0b0](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/44330b91eb552fd20ef6f2e69bf5e6f1e8f5c0b0).
The new [machine register](../../config/pon/pq128-lifetime-composition-v2.json),
[checker](../../scripts/ci/pq_lifetime_composition.py), and
[tests](../../scripts/ci/test_pq_lifetime_composition.py) preserve the existing
[V1 lifetime contract](PQ128_LIFETIME_BUDGET_V1.md) and
[root dependency contract](PQ_ROOT_DEPENDENCY_REGISTER_V3.md).

## 1. What the source bridge establishes

The legacy V1 budget declares 15 source paths at
`12e510b211110d93d9ead07e02c07a1eecc28ae9`. The root V2/V3/V4 inventory
declares 37 paths, with `57e6c17ae2fa8a9cc547e271f34d90ef09115f04` as review
base context. That latter revision is not a claim that all continuation files
already existed at the review base. The shared path is
`trillionnium/crates/trnm-release-bundle/src/pq_release.rs`.

The V2 inspector requires both exact manifest identities, invokes both existing
inspectors, checks the overlapping source digest, and reports the union:

| Inventory | Declared paths |
| --- | ---: |
| Legacy lifetime | 15 |
| Root and provider continuation | 37 |
| Shared path | 1 |
| Distinct union | 51 |

An exact manifest change requires a new review. One source map cannot silently
overwrite the other. Missing inputs, locks, sources, changed bytes, conflicting
digests and attempted qualification changes are refused. The existing
descriptor-bound regular-file reader remains in use.

`declared_source_union_consistent=true` means consistency of these reviewed
declarations and the bytes inspected. It does not establish an atomic snapshot
across separate reads, authenticated Git history, deployed executable identity,
complete call-graph coverage, transitive dependencies, trusted custody, or an
implementation-to-theorem refinement. The joint report deliberately keeps
`source_revision_bound=false`, `deployment_identity_proved=false`, and
`transitive_dependency_closure_proved=false`.

## 2. Public primitive identities have one shared scope

Both input registers refer to the same four fixed public primitive identities:

| Shared scope | Public parameter identity |
| --- | --- |
| SHA-256 | `FIPS180-4/SHA-256` |
| SHA-512 | `FIPS180-4/SHA-512` |
| SHAKE128 | `FIPS202/SHAKE128` |
| SHAKE256 | `FIPS202/SHAKE256` |

The bridge retains each legacy term and each root use group under these four
identities. It does not create eight independent query budgets merely because
there are two registers. It neither adds nor takes a minimum of their budgets.
All four maxima and query-unit mappings remain unknown. A changed maximum,
unit, fixed-public identity, or reset policy requires an explicit new review.
Registration, role changes, key rotation, recovery and epoch changes do not
restart preprocessing or the lifetime scope.

The existing root inventory already records the actual algorithm dependencies:
ML-DSA uses SHAKE128 and SHAKE256; SLH-DSA-SHA2-256s uses both SHA-256 and
SHA-512, including HMAC-SHA-512 and MGF1-SHA-512. This V2 bridge connects that
inventory to the older scope; it does not claim to have newly implemented those
cryptographic dependencies. See [FIPS 204, section 3.7](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
and [FIPS 205, section 11.2.2](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf).

A separate obligation now records the shared `KECCAK-p[1600,24]` substrate of
SHAKE128 and SHAKE256. [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
specifies these different modes over that permutation. Their interface names
alone do not prove independent random oracles. One XOF call, a squeeze block,
and a permutation call are different units; no equation adds these counts
without a justified resource transformation. The substrate mapping and joint
oracle replacement error remain unknown. Other SHA3 proof profiles are not
included by this declaration.

## 3. Root AND composition and the location of losses

Fix one complete experiment, adversary class and lifetime. Let `C` be a common
failure event, and let `B_ML` and `B_SLH` be failures of the complete threshold
family games. The required project relation is:

\[
\mathrm{Bad}_{root}\subseteq C\cup(B_{ML}\cap B_{SLH}).
\]

This relation is an open project obligation. In particular, it requires the
same full statement, purpose, current roster, thresholds, distinct signers,
successor possession, policy transition and owner authority. Corruption,
custody, rollback, revocation, retained liabilities and actual external effects
cannot be removed by describing the verification rule as AND.

Suppose the family bounds, after their own reductions, are valid in the same
game. If their event and reduction errors are respectively
`epsilon_ML, delta_ML` and `epsilon_SLH, delta_SLH`, the conservative rule is:

\[
\epsilon_{root}^{declared}
=\min\!\left(1,\delta_C+\delta_{shared}
+\min(\epsilon_{ML}+\delta_{ML},\epsilon_{SLH}+\delta_{SLH})\right).
\]

`delta_shared` denotes one separately justified common-game replacement loss.
The theorem game, resource expansion and placement of that loss must actually
apply; the checker only validates matching declarations. The proof of the
probability rule uses the union bound and the fact that an intersection is
contained in each member. Neither step requires independent events.

The family-specific loss belongs in its own branch before taking the minimum.
For example, with family pairs `(1/64, 1/4096)` and `(1/4096, 1/64)`, both
complete family sums are `65/4096`. Selecting the minimum event error and the
minimum reduction error separately would produce `2/4096`, which is not the
bound supplied by either family. The tests exercise this distinction.

The default API does not implement multiplication of family probabilities.
Taking `B_ML = B_SLH` with probability `p` gives intersection probability `p`,
not `p squared`. A caller-supplied `independent=true` is not a proof and is
refused. The 2-of-3 rule also does not create a square automatically: the
corruption model and reduction from threshold acceptance to multi-user forgery
must be established. Successor possession uses all three keys in each family;
the arithmetic declaration retains that separate role scope.

## 4. Unknown inputs remain visible

The root arithmetic API has six mandatory inputs: two family event bounds,
their two reduction losses, common failure, and shared game replacement.

| Condition | Arithmetic behavior |
| --- | --- |
| A family event or its reduction loss is unknown | That family's complete bound stays unknown |
| One complete family has a valid declared bound | It can bound the intersection; the other unknown remains listed |
| Common failure or shared replacement is unknown | The complete conditional root bound remains unknown |
| A zero loss is claimed | It must be explicitly declared with its unverified theorem reference |
| A probability sum exceeds one | Keep the exact uncapped sum and report a final probability upper bound capped at one |
| Input fields claim product, verification or independence | Refuse the unsupported contract |

All arithmetic uses the existing bounded exact rational implementation. A
reference, locator or applicability string is review input, not a theorem
verifier. Numeric declarations, including extremely small caller-supplied
values, remain unverified. Matching experiment labels establish only label
agreement. They do not establish that the underlying games, auxiliary quantum
states, profiles or reductions are compatible.

`review_arithmetic(data)` accepts the closed research-model or arithmetic-example
contract. `validate_manifest(data)` checks declarations only and never reports
source inspection. `inspect(root, manifest)` additionally invokes the two real
source inspectors. None of these APIs produces an actual lifetime failure bound.

## 5. Resource conversion still needs evidence

Each common/shared/family resource instance now has explicit unknown fields for
total adversary queries, online queries, offline search, preprocessing, honest
queries, simulator and extractor queries, classical advice bits, quantum advice
qubits, keys, rosters, epochs, signing queries and verification attempts.

The coverage labels include failed, cancelled, rejected and unpublished work,
helpers, recursion, shared uses and authority surviving retirement. These labels
overlap. They are a coverage checklist, not disjoint bins to sum. In particular,
an offline failed query may also be a shared-primitive query. Quantum access
models and resource units must be fixed before a numeric transformation is used.
Whether honest, simulator and extractor work enters a theorem's query count is
theorem dependent. Unknown advice does not mean no advice.

An honest node's timeout, message-size limit, local signature cap or observed
receipts cannot bound work on an adversary's external machines. Those limits
remain useful operational controls, but the total adversary resource bound
requires a separate justified model or explicitly stated external assumption.

## 6. Eight target allocations do not become a joint bound

The legacy register still allocates eight times `2^-131`, exactly `2^-128`.
The new report computes `allocation_headroom = 0`. Extra shared losses have
`placement_in_eight_domains=unproved` and `total=null`; there is no implicit
zero loss and no assertion that the actual system has exceeded a risk target.
This implementation does not include a general additional-loss allocation
solver. A positive extra charge outside a fully used target would require
reallocation, once that charge and its placement were validly established.

The old domain experiment and the root inventory have not been mapped into a
proved common whole-chain experiment. Therefore the root result is not
substituted for the legacy signature term and is not added to the eight-domain
sum. The report labels them `legacy_declared_arithmetic` and
`conditional_root_arithmetic`, with `joint_bound_derived=false` and both scope
mappings unproved. Their events may overlap; no domain is silently removed.

All of the following remain required:

- A finite lifetime or explicit stopping rule, including earlier preprocessing
  and authority surviving retirement.
- Complete key/epoch populations and concrete multi-user threshold-family
  bounds under the actual corruption and custody model.
- Shared-oracle instantiation, initial advice, query units and all reduction,
  simulator/extractor, compiler and recursion losses where applicable.
- Project event containment, implementation refinement and complete protected
  outcome coverage, including recovery and actual external effects.
- The ledger/network/work-cost conditions for a whole-chain claim. No RISC Zero,
  Plonky3 or tagged SHA3 proof estimate is imported into this native PNW1 scope.

[RFC 9955, section 1.3.2](https://www.rfc-editor.org/rfc/rfc9955.html#section-1.3.2)
discusses proof composability and dependencies on additional hashes or KDFs.
It is an informational framework, not the missing proof of this project's
threshold protocol. NIST security categories likewise do not supply a direct
whole-lifetime failure probability.

## 7. CI and interpretation

Run from the repository root:

```sh
python3 scripts/ci/test_pq_lifetime_composition.py -v
python3 scripts/ci/pq_lifetime_composition.py --root .
```

Both commands are mandatory in `repository-truth`, immediately after the
unchanged V1 budget commands. CI structure controls reject deletion, duplication,
conditional skipping, swallowed failure, movement to another lane, or replacement
of the checker/test file by a symlink. The four new source/config/document files
also enter the explicit research corpus and exact Git blob pins. Every existing
V1, claim-guard, root, protocol and native gate is retained.

The tests include independent finite-space evaluation of 4,096 event triples,
loss-placement and unknown-input cases, scope/profile conflicts, real declared
source inspection, and source/input refusal controls. They test the mathematics
of the accounting rule and the checker contract; they are not quantum attack
cost measurements or a project security proof.

A successful inspection returns exit zero with **HOLD**. A malformed or changed
contract returns exit two with **REFUSE**. Neither grants consensus admission,
release, migration, payment, installation, execution or FinalUse. The actual
report continues to contain:

```json
{
  "actual_lifetime_failure_bound": null,
  "composition_coverage_proved": false,
  "whole_chain_hash_query_scope_closed": false,
  "whole_chain_pq_qualified": false,
  "production_activation": false
}
```
