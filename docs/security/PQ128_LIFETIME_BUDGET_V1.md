# Whole-chain PQ128 lifetime budget contract V1

Status: **research only; HOLD / NO-GO**. This contract is a budget-review aid,
not a cryptographic proof, production activation, or an attestation that the
chain has a failure probability of at most `2^-128`.

The original implementation baseline is PQ integration candidate
[`12e510b211110d93d9ead07e02c07a1eecc28ae9`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/12e510b211110d93d9ead07e02c07a1eecc28ae9).
The [machine-readable register](../../config/pon/pq128-lifetime-budget-v1.json)
and [budget checker](../../scripts/ci/pq_lifetime_budget.py) extend the existing
[whole-chain claim guard](WHOLE_CHAIN_PQ_CLAIM_GUARD_20261031.md). They do not
transfer an observation or security estimate from another candidate to this one.

## Current consolidation source binding, 2026-11-13

The unchanged **21-path** event roster now binds to source checkpoint
`2bb56596e637908c44b5a2ef5984c9c37c7d3cc8`, tree
`18cfc660131170a5b0c5c7244987a9fcebfb7e62`. Each SHA-256 comes from
the exact regular Git blob named by that checkpoint. The source lock and
`experiment.source_revision` name the same checkpoint; the lock-byte SHA-256 is
`0e3f0676473d0c0f585af436cfd566bf68acc369517129a78eb75f685bb75dc1`.

The prior 21-path declaration named
`e6aed30916d244a0e60ac06c90e1b97abd53225b`. It remains a historical
source identity. The earlier 15-path records below retain their original
rosters, dates, digests and observations; they are not the active 21-path lock.
Binding metadata does not replay those observations on this successor.

Only the reviewed source mapping changes. The original event sets, numerical
allocations, assumptions, unknown terms and query budgets remain unchanged.
The actual lifetime bound stays null; all qualification fields remain false
and the result stays HOLD. This listed-path review supplies no native execution,
complete dependency closure, production activation or cryptographic proof.
The metadata successor must pass its own ordinary source and contract checks.

## 1. Specify the claim before assigning numbers

Fix a security experiment consisting of the protocol/profile and implementation
identities, a finite lifetime or explicit stopping rule, the adversary class and
resource bounds, all oracle interfaces, initial advice, and environmental
assumptions. Specify the protected outcomes: accepted unauthorized state,
incorrect accepted work, incorrect canonicality/finality, duplicate external
effects, or use of unauthorized/revoked content. Availability and confidentiality
need their own declared outcomes if included. A cryptographic integrity claim
alone does not imply either.

`Pr[Bad] <= 2^-128` in this experiment is a probability claim. A statement about
128-bit attack cost or a NIST security category is a different claim. Neither
supplies a numerical failure probability without the adversary's resources,
success criterion, number of instances, and applicable reduction.

The current register records eight **audit domains**, not a theorem that exactly
eight independent events exhaust every system failure. Their source paths show
where the obligations arise; file presence is not proof of implementation
correctness. A composition/coverage proof remains required.

| Domain | Bad event to formalize | Concrete owner or interface | Missing numerical qualification |
| --- | --- | --- | --- |
| Signature | An accepted authorization is attributed to an uncompromised authorized key without a permitted signing action | `trnm-crypto-primitives/src/pq_auth.rs`; native accounts and task authorization | Concrete multi-user/multi-message quantum forgery game, key lifecycle and all actual verifier entrypoints |
| Commitment | A content/state/manifest binding accepts a different semantic object under the same authenticated commitment | `trnm-data-availability/src/cell/manifest.rs`, `model_root.rs`, `pq.rs` | Per-purpose binding, canonical encodings, shared-hash model, precomputation and parameter mapping |
| Proof | A verifier accepts a false complete W1 statement | `trnm-crypto-primitives/src/pon_work.rs`; separate candidate proof backends | Native implementation-to-relation refinement; for a succinct backend, concrete PCS, Fiat-Shamir, recursion and quantum reductions |
| Ledger | An adversary violates the declared canonicality/confirmation property within the experiment | `trnm-pon-node/src/consensus.rs` and `store.rs` | Joint W1 work, branch DAA, timestamps, cumulative work, network and quantum strategy model |
| Transport | An authenticated session/message is accepted with the wrong peer, context or freshness | `trnm-pon-node/src/ingress/pq_network.rs` and transport owners | Composed session game, actual KEM/authentication interfaces and replay/eclipse assumptions |
| Recovery | Recovery/migration accepts stale authority, loses a liability or repeats an external effect | native account migration and `trnm-pon-node/src/pq_rollback_witness.rs` | Complete state split, external monotonic witness assumptions, migration and effect reconciliation |
| Release | Current-use authorization permits unauthorized, stale or mismatched loaded bytes | `trnm-release-bundle/src/pq_release.rs`; M15 and Hepta consumers | Independent roots, quorum/revocation, exact loaded-byte identity and rollback-safe current-use semantics |
| Application | A task, payment, settlement or FinalUse crosses an authority boundary without its complete valid contract | M06 funding/payment, settlement and `trnm-research-protocol/src/hepta_handoff/pq.rs` | Cross-owner refinement, independent evaluation/custody and actual effect binding |

These descriptions can overlap. A proof must explain which underlying break
covers each protected outcome. The checker requires unambiguous accounting of
coverage and named losses; it does not infer that mapping from labels.

## 2. Composition and adaptive histories

In one fixed experiment and adversary class, suppose

\[
\mathrm{Bad}\subseteq\bigcup_i B_i,
\qquad\sup_A\Pr[B_i]\le\epsilon_i.
\]

Then `sup_A Pr[Bad] <= sum_i epsilon_i`. Independence is unnecessary. If a
reduction bounds `B_i` only up to earlier failures, use a first-bad-event
partition or include the earlier-event terms explicitly. It is invalid to
silently treat a conditional game as an unconditional one.

For a per-opportunity bound, let `tau` be the first failure time, let `F_(t-1)`
be the preceding classical history, and let `b_t` be a predictable nonnegative
allowance. A sufficient interface is

\[
\Pr[\tau=t\mid\mathcal F_{t-1}]
\le {\bf1}_{\{\tau\ge t\}}b_t,
\qquad
\sum_t{\bf1}_{\{\tau\ge t\}}b_t\le B\quad\text{almost surely}.
\]

Taking expectations and summing gives `Pr[tau < infinity] <= B`. A deterministic
cap `N` and a uniform conditional bound `epsilon` give `B = N epsilon`.
The v1 checker uses this bounded-count special case; it does not certify a
general optional-stopping or predictable-budget theorem.

The required theorem must cover the actual adaptive transcript and allowed
residual quantum side information. It is not legitimate to measure an adversary's
quantum state merely to fit a classical log. A marginal or root-game bound need
not remain the same after conditioning on a rare advantageous history.
For example, after learning a uniform `Z` in sixteen values, selecting the event
`E_Z = {Z equals Z}` succeeds with probability one, although each event selected
in advance has probability `1/16`.

A whole-lifetime or multi-instance theorem can be used directly when it covers
the full experiment. Do not multiply its error again by the users, calls or
epochs it already includes. Conversely, a per-instance theorem cannot cover an
unbounded collection just by being relabelled as a lifetime theorem.

For an ideal-model replacement the interface is instead of the form

\[
\Pr_{\rm real}[\mathrm{Bad}]
\le\epsilon_{\rm simulation}
+\sum_i\epsilon_i(\mathcal R_i(\mathbf q,S)).
\]

The resource transformation `R_i`, simulator/extractor queries, advice overhead
and replacement error must be recorded. Shared-hash replacement losses require
one explicit accounting decision. Double inclusion can make an estimate more
conservative, but is not exact accounting; removing a term without a valid
mapping can invalidate the bound. A repeated loss identifier is therefore an
ambiguous contract to resolve, not proof of a cryptographic attack.

## 3. A lifetime includes unseen work

Keep these quantities distinct:

| Quantity | What it can establish |
| --- | --- |
| Protocol-enforced message/verification cap | An upper bound on the specific online interface actually limited, subject to enforcement/refinement |
| Observed node receipt or log count | A lower inventory of observed activity, not all adversarial activity or future activity |
| External adversary resource assumption | A declared bound on otherwise unobservable attack resources, with an explicit model and justification |
| Unknown resource or initial advice | A missing condition; never an implicit zero |

Include failed, cancelled, rejected, discarded and unpublished attempts, offline
search, preprocessing, helpers, recursive work and every relevant interface.
Whether honest, simulator and extractor queries appear in a theorem's `q` must
be fixed from that theorem. Counts with different meanings cannot be added or
substituted without a unit/model mapping. An expected number of calls is not an
almost-sure cap; a theorem for an expected budget would need a different proof.

Assign identities to the actual fixed public primitives and shared interfaces.
The same public hash across accounts, branches, domain tags, key rotations,
restarts and epochs retains one lifetime resource scope. None of those labels
erases preprocessing. A fresh-instance argument requires its own randomness,
advice-independence and reduction obligations. Do not reset a counter merely
because a key or epoch changes.

If precomputation is bounded by queries, count those queries. If a theorem
instead permits bounded classical/quantum advice obtained by arbitrary
precomputation, record the advice type/size and that theorem's online resource
tradeoff. These are different models, not two names for a node log.

## 4. Exact arithmetic is useful, but does not establish security

The user's budget example is exact:

\[
8\cdot(2^{32}\cdot2^{-163})
=8\cdot2^{-131}=2^{-128}.
\]

This is an illustrative allocation. There is no project theorem here supplying
the per-opportunity `2^-163` values or a complete `2^32` lifetime cap. The
checker separates the allocation, conditional arithmetic, and actual
qualification. Unknown terms leave the actual bound `null`. A known subtotal
is explicitly partial and is not a whole-chain upper bound.
The equal split consumes the entire target: any additional simulator or
composition loss must already be included in a charged term, or the allocations
must be revised. There is no unallocated margin for a later extra error.

In contrast, eight classes with `2^32` opportunities each and a valid per-call
bound of only `2^-128` would give a union upper bound `2^-93`. This does not
claim an attack achieving that probability; it shows that those premises do
not prove the requested `2^-128` bound.

The tool uses exact rational values rather than float tolerances. Equality at
the target is distinguished from any positive excess. It rejects malformed
numeric encodings, duplicate JSON fields, conflicting model/profile identities,
ambiguous losses and unsupported promotion. Supplying a theorem URL, hash or
`verified` boolean is not a machine-verifiable proof of theorem applicability.

The [separate arithmetic-example input](../../config/pon/pq128-lifetime-example-v1.json)
is tagged `arithmetic-example` and uses an explicit `illustrative` revision
marker. The normal guard refuses this purpose in place of the current research
register. In the real register, the equal `2^-131` allocations remain a proposed
split only; all derived event bounds are unknown.

The V1 schema currently accepts declared per-invocation, multi-instance and
whole-lifetime event terms. A separate hybrid-distance/reduction engine is not
implemented. Shared-model replacement, resource transformations and complete
event coverage remain explicit obligations even when all event arithmetic is
numeric. Therefore `model_arithmetic_sum` is only the supplied event-term sum,
never a complete real-world security bound.

### Machine interface

`evaluate(data)` validates the closed input schema and performs arithmetic. It
does not inspect files, so `source_revision_bound` is false,
`source_binding_scope` is `unbound`, and `source_lock_sha256` is null.

For a `research-model`, `inspect(root, manifest)` additionally requires the
reviewed [source lock](../../config/pon/pq128-source-lock-v1.json). Its namespace
is `trnm-pq128-source-lock-v1` and its exact fields are `schema`,
`source_revision`, and `files`. The lock revision must equal the manifest's full
40-character lowercase commit identifier. The `files` object must contain
exactly the union of the events' `source_paths`, each mapped to a full lowercase
SHA-256 digest. Missing and extra paths are both refused. The manifest, lock,
and every named owner file are read through the existing descriptor-bound
regular-file reader. Every actual file digest must match the reviewed lock;
there is no fallback to reporting unbound hashes if the lock is unavailable or
does not match. Duplicate JSON fields, symlinked inputs, and oversize locks are
refused.

After these checks, the report has `source_revision_bound: true`,
`source_binding_scope: declared-event-paths-only`, and the SHA-256 identity of
the exact lock bytes. This means consistency with the reviewed lock. The
runtime checker does not access Git history and therefore works in shallow CI
checkouts. It does not authenticate the lock's origin, prove Git ancestry,
establish a complete dependency closure, check deployed executable bytes, or
make multiple file reads into an immutable snapshot. An actor who can replace
the manifest, lock, and sources together can create a different consistent
declaration; review and repository source-integrity checks remain separate
gates. These SHA-256 values are source-review checksums, not upgraded protocol
content commitments or numerical quantum-security guarantees.

The arithmetic example remains unbound even if its revision field happens to
contain a syntactically valid commit ID or a matching research lock exists.
Its source hashes describe the bytes read for the example only. All security,
theorem-applicability, composition-coverage, and activation flags remain false
in both modes, and the actual lifetime failure bound remains null.

### Published runtime source mapping, 2026-11-12

The source lock and `experiment.source_revision` now both name published
runtime checkpoint
[`523bee8709645e7dbc3455f1dc74737f7067af62`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/523bee8709645e7dbc3455f1dc74737f7067af62),
tree `5fdd5f7073a91d210c82411a37c8982d4159f29b`. The 15 exact regular Git
blobs were read again at this revision and compared with the working regular
files. All 15 file hashes remain identical to the local Runtime A review below.
The new lock-byte SHA-256 is
`5714721c9ebc841d04e88c923cc649fbe061cc25c3b0497bce3b6f8d1b887405`.

Only the revision fields change. Event sets, numerical allocations, assumptions,
eight unknown terms, four unknown query budgets and false qualification fields
are unchanged. The actual lifetime bound remains null and the result remains
HOLD. The Root register is unchanged. The published runtime has Runtime A's
tree but a distinct commit identity; tree equality and the retained former
Metadata B observation are not new execution evidence. The metadata successor
must pass its own source and execution gates. The original local review and
its failure observations remain below with their original identities.

### Retained local Runtime A source mapping, 2026-11-12

The 15 declared source paths are reviewed against Runtime A,
`b3bc526b96d3a8e2ad0be7faa4f00f11d9f7ea53`,
tree `5fdd5f7073a91d210c82411a37c8982d4159f29b`. For each path, review checked
the exact regular Git blob and compared `git show` bytes with the working
regular file. The source lock and `experiment.source_revision` both name
Runtime A. The lock-byte SHA-256 is
`40e4035ffd1641288fc18c0fe18733f51c7c930a85212d570cef1fdf85d8bd27`.

Fourteen pins retain the preceding `7f83ea843d6d1578a475a7a0c4dc026da564a795`
mapping. The only changed pin is
`trillionnium/crates/trnm-service-settlement/src/native_budget.rs`:

```text
prior:    1fd964a4bfb3dec372c04a32853d9b08a3b80773d3182099d80705ab916ace38
reviewed: 04f10f76d9f3bcdbe2df1b0bf3182d3e5d66a8f3974982a3491f156e50ba7c68
```

The reviewed change adds the native journal path check and calls it before the
original budget store opens SQLite. It inspects the original OS path and its
`-journal`, `-wal` and `-shm` sidecars using `symlink_metadata`; existing objects
must be regular files, only `NotFound` means absent, and other inspection errors
are returned. Regular recovery sidecars remain permitted. The containing
directory is still a trusted boundary; this does not prevent a concurrent path
swap or qualify currency backing, service delivery or external effects. Other
modules that call the helper are not automatically included in these 15 paths.

The lifetime manifest differs only at `experiment.source_revision`. Its event
sets, numerical allocations, assumptions, eight unknown event terms, four
unknown query budgets and all false qualification fields remain unchanged.
The actual lifetime failure bound remains null and the result remains HOLD.
The reader executed before this update returned exit 2 with
`source lock hash mismatch` for `native_budget.rs`; that old-mapping refusal is
retained. This metadata successor supplies a reviewed declared-path binding,
not a native execution result or a complete dependency closure, and still
requires final-source validation. The separate 43-path Root register is
unchanged by this review.

### Retained joint-source mapping

The 15 declared paths are bound to `8add285b6c0a91d8b7812efe2d02c9342f74c91b`, tree `8aaa486aa4ccd4e41e33241fb4e7e273d3c3d5f6`.
Only `trnm-pon-node/src/store.rs` differs from the preceding 15-path lock: the
account-scope check now guards fresh/cold/warm Node ownership before execution.
The original event sets, equations, unknown terms and qualification flags are
unchanged. V5 witness custody and entropy obligations are recorded separately
in the Root register; their absence from this 15-path roster remains explicit.
A metadata child stores this lock; its own exact source requires separate
validation. The lifetime bound remains unknown.

### Earlier composed-source mapping

The then-reviewed 15-path lock is reviewed against the published runtime checkpoint
[`ef6df12a042912664df64f2112c2b1c600dce9fa`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/ef6df12a042912664df64f2112c2b1c600dce9fa),
whose Git tree is `5e89951169fe2d5ef7418c3dc23984babda172ce`.
Its lock-byte SHA-256 is
`84a7fb53e5ee99bb04cf32cb0392a7fed8c40c1f535dbae6f50ae0e2b0414cf2`.
For every declared path, review checked the exact regular Git blob (mode
`100644` or `100755`) and byte equality with the candidate regular file before
rebinding. All 15 paths matched. Compared with the preceding lock, only the
`consensus.rs` and `ingress/pq_network.rs` fingerprints change. The former adds
test helper/vector coverage; the latter requires complete SPKI equality after
the peer-identity lookup. The manifest differs only at
`experiment.source_revision`.

The revision identifies these 15 declared source blobs in the published
runtime checkpoint. A subsequent metadata commit carries this reviewed
mapping; its complete tree differs from the runtime checkpoint. The binding
scope remains `declared-event-paths-only`, with the checker and its refusal
rules unchanged.

The original [repository-truth failure](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42830743518/job/129995452145)
at `e4abb172147e941b62483652b0ceabaae4317624` remains evidence for that source:
58 tests ran with one error, the stale `consensus.rs` source-lock hash.
Post-rebind test results require a separately frozen candidate. The eight
unknown event terms, four unknown shared-primitive query budgets, null actual
lifetime bound and HOLD remain unchanged. Complete dependency coverage and
cryptographic provenance remain unestablished; all qualification flags remain
false. CI continues to verify the reviewed mapping and cannot silently
regenerate it from arbitrary current bytes.

### Preceding composed-source mappings

### Retained earlier composed-source mapping

The then-reviewed 15-path lock is independently reviewed against exact source
`b7e38fdc2e43c468692abc52aec03737f2df7f1b`, tree
`b75d318fc7b7b027a810f4a70a9cd91e0b3930f8`. Its lock-byte SHA-256 is
`af0ceb6ae756031305b9b73f1b6695664c830558fed7a13b6c2e7ff255592f92`.
The [original-budget continuation review](../../evidence/chain-throughput-budget-20261110-065438/source-lock-review/README.md)
and its [per-path comparisons](../../evidence/chain-throughput-budget-20261110-065438/source-lock-review/publication-reanchor.json)
retain all 15 exact Git regular-blob and working-file comparisons. Thirteen
fingerprints are unchanged. The `consensus.rs` change is the existing test-only
integer-vector continuation that caused the original e4abb source-lock refusal;
`store.rs` exposes the existing progress-aware state reader within the crate.
The manifest differs only at `experiment.source_revision`. The original failed
CI observation and the frozen-source pre-rebinding refusals remain retained.
This maintenance does not claim that the updated declarations were already in
the source checkpoint or that its native/business gates passed.

### Retained composed-source mapping, 2026-11-09

The preceding 15-path lock was independently reviewed against exact source
`66b7064be597039ce871b5b12ad5568850a2dd46`. Its lock-byte SHA-256 was
`29ba9abdbb39d96bece885a0cd821fd9ad428413974cd530d26434f5a7daf84a`.
The [preceding composition review](../../evidence/cell-storage-convergence-f2568-20261109/README.md)
and its [source-maintenance inventory](../../evidence/cell-storage-convergence-f2568-20261109/ci-source-maintenance19.members.json)
preserve the prior files, the original refusal, all 15 Git regular-blob and
working-file comparisons, and isolated original Python controls.
At that review, only the `cell/pq.rs` fingerprint and the declaration revision

The [retained composition review](../../evidence/cell-storage-convergence-f2568-20261109/README.md)
and its [source-maintenance inventory](../../evidence/cell-storage-convergence-f2568-20261109/ci-source-maintenance19.members.json)
preserve the prior files, the original refusal, all 15 Git regular-blob and
working-file comparisons, and isolated original Python controls.
In that mapping, only the `cell/pq.rs` fingerprint and declaration revision
changed; the manifest differed only at `experiment.source_revision`.

The earlier mapping named `0f0592ace4b08a1d39e1ffad31beee76ddc4fd66`
and lock SHA-256 `8771ac5c7bfff29266a89e7b65bf1d57a021fd38a0461b7cc937db58c34557b0`.
Its [earlier composition review](PQ_COMPOSITION_SOURCE_LOCK_REVIEW_20261108.md)
remains unchanged.

### Original source-lock generation record

The original lock was generated from the 15 declared event paths at commit
`12e510b211110d93d9ead07e02c07a1eecc28ae9`. For every path, generation checked
the exact `git ls-tree` entry was a regular blob with mode `100644` or `100755`,
read `git show <revision>:<path>`, and compared those bytes with the current
regular file before recording its SHA-256. All 15 comparisons matched. The
lock's SHA-256 is
`97d8c0a229f1f863c5f54a800f1405a4a68f60cac5899b4f2973deeb000900c8`.
This is evidence of how this review artifact was constructed, not a signature
or a theorem about the complete program. A future source change requires a
new reviewed mapping; CI must not silently regenerate the lock from whatever
bytes it is checking.

The following historical command requires the original source/lock checkout.
The current mapping uses the separate checkpoint and reviewed per-path digests
stated above. No command silently rewrites the lock:

```sh
python3 - <<'PY'
import hashlib
from pathlib import Path
import subprocess
import sys
sys.path.insert(0, 'scripts/ci')
import pq_lifetime_budget as budget
from pq_source_reader import read_regular
root = Path.cwd()
manifest = budget.strict_json(read_regular(root, budget.DEFAULT_MANIFEST, budget.MAX_BYTES))
lock = budget.strict_json(read_regular(root, budget.DEFAULT_SOURCE_LOCK, budget.MAX_BYTES))
revision = '12e510b211110d93d9ead07e02c07a1eecc28ae9'
assert revision == lock['source_revision'] == manifest['experiment']['source_revision']
paths = {path for event in manifest['events'] for path in event['source_paths']}
assert paths == set(lock['files'])
for path in sorted(paths):
    entry = subprocess.check_output(['git', '--literal-pathspecs', 'ls-tree', '-z', revision, '--', path])
    metadata, name = entry.removesuffix(b'\0').split(b'\t')
    mode, kind, oid = metadata.decode().split()
    assert mode in ('100644', '100755') and kind == 'blob' and name.decode() == path
    blob = subprocess.check_output(['git', 'show', revision + ':' + path])
    assert blob == read_regular(root, path, budget.MAX_BYTES)
    assert hashlib.sha256(blob).hexdigest() == lock['files'][path]
print('Matched declared event paths:', len(paths))
PY
```

Probabilities are objects with canonical decimal-string `numerator` and
`denominator`; call/query counts also use decimal strings. Duplicate fields,
floats, invalid Unicode and undeclared fields are refused. Inputs are bounded to
1 MiB, 128 entries per list and 4096 bits per exact arithmetic result. Exceeding
these limits refuses the computation instead of rounding or clipping an error.
`partial_arithmetic_sum` reports only known declared terms;
`model_arithmetic_sum` remains null if any required event term is unknown.
`actual_lifetime_failure_bound` is always null in this research schema.

## 5. Conditions without a probability model

Implementation correctness, sufficient independent custody, protected external
state, complete recovery/effect reconciliation and the declared network model
are proof obligations or environmental assumptions unless an explicit stochastic
failure model is supplied. This register does not assign them arbitrary small
probabilities.

If a result only establishes `Pr[Bad | H] <= epsilon`, it does not establish an
unconditional bound without accounting for `not H`. When a legitimate model
also gives `Pr[not H] <= delta`, `Pr[Bad] <= epsilon + delta` follows. Merely
accepting a list of assumptions is not a measurement of `delta`.

## 6. Literature and candidate boundaries

[NIST's security evaluation criteria](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-%28evaluation-criteria%29)
define resource-comparison categories, not whole-chain failure probabilities.

Carolan, Poremba and Zhandry,
[(Quantum) Indifferentiability and Pre-Computation](https://eprint.iacr.org/2024/1727)
([full paper](https://arxiv.org/pdf/2410.16595)), introduce a stronger composition
notion for preprocessing. Their one-round-sponge application requires its
specified random-permutation model and parameters. It does not instantiate the
current fixed shared Poseidon2 primitive.

Alagic, Carolan, Majenz and Tokat,
[The Sponge is Quantum Indifferentiable](https://arxiv.org/abs/2504.16887), give
quantum indifferentiability results. An asymptotic result without instantiated
constants and resource transformations cannot supply a precise project error.

Chiesa, Di, Hu and Zheng,
[How to Prove Post-Quantum Security for Succinct Non-Interactive Reductions](https://eprint.iacr.org/2025/2166),
EUROCRYPT 2026, require the relevant restoration and extraction properties.
The current profile-to-theorem mapping remains an obligation.

The separate [P3 shared-primitive audit](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/cc836dfc13ef0006eb0878abd8cb5eca9a76bec0/formal/pon-nakamoto-v1/w1_public_stark_research/security_model_audit/INTEGRATION.md)
retains an unrestricted-compressor counterexample. It does not establish that
those inputs are reachable Merkle children or that a complete W1 forgery exists.
Its conditional RBR estimate is not a concrete whole-chain lifetime bound.
The [RISC0 QROM mapping candidate](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/778)
also requires its own exact implementation and parameter mapping. These
candidates cannot inherit each other's numeric security estimates.

## 7. Reproduction and closure criteria

Run from the repository root:

```sh
python3 scripts/ci/test_pq_lifetime_budget.py -v
python3 scripts/ci/pq_lifetime_budget.py
python3 scripts/ci/pq_lifetime_budget.py --manifest config/pon/pq128-lifetime-example-v1.json
python3 scripts/ci/test_pq_chain_claim_guard.py -v
python3 scripts/ci/pq_chain_claim_guard.py
python3 scripts/ci/check_pq_research_integration.py
```

An exit-zero HOLD result means the research accounting contract was accepted;
it never authorizes consensus, release, installation or FinalUse. The separate
[validation record](../../evidence/pq128-lifetime-budget-20261108/README.md)
retains actual command outcomes, including unavailable gates.

To advance the security claim, independently review the protected outcomes
and coverage reduction; fix the deployed source and all profile parameters;
instantiate the complete concrete theorems and resource transformations; give
the lifetime, advice and adversary resource model; discharge the nonprobabilistic
implementation/environment obligations; then compare the complete derived sum
with its declared target. Any future attestation needs a separately reviewed
schema. This V1 research checker deliberately has no promotion switch.
