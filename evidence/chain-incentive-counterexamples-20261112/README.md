# Retained incentive counterexamples and scoped native observations

Status: **development evidence; production HOLD; economic security unqualified**.
This record preserves two different outcomes: the complete-roster successor closes
with the same native state across independent arrival orders, while the existing
V4 reward rule admits a known-source splitting counterexample. A passing
counterexample test means the weakness was reproduced. No reward rule, signed
domain, source map, corpus or production setting was changed to remove it.

The source commits are:

- Base C5: `6ac9a79c2fb37d6102c526c354fe2d448a9f4e6d`.
- Complete-roster regression: `3b97b97f3a3387532b00594d3805186143ac6f45`.
- V4 regression and its limits: `8197606d844e9d4c79c068a07746fabf2506fed4`,
  tree `7321c6d24ac25992f54595bda868ef94112adf40`.

This evidence-only continuation does not retroactively qualify a later merged
source. [OBSERVATIONS.json](OBSERVATIONS.json) records the measured scope, and
[MANIFEST.json](MANIFEST.json) binds copied original files to their byte lengths
and SHA-256 digests. Runtime logs use `.txt` or lossless `.txt.gz`; their decoded bytes are unchanged.

## What actually completed

| Observation | Result | Exact scope |
| --- | --- | --- |
| Retained revision3 ordering and exact-copy tests | 2 native/reference tests passed | The real `pon_execute` binary, six score permutations and 1/2/4/8 worker parameters; historical first-pair outcomes remain 10 or 100, and the late third evaluation rejects. |
| Complete public-evaluation integration module | 8 native tests passed, 6.25 seconds | Source `3b97`; includes 144 independent commit/reveal order and worker combinations, plus 12 missing-member/worker cases. |
| Public model/reference oracles | 19 unique tests passed | Composition, evolution, task-window and quorum Python oracle suites. Initial and frozen repeats are retained; they are not 38 independent tests. |
| CI source-integrity negative controls before `819` | 43 tests passed | Source-checker tests, not native model execution or efficacy. |
| Preliminary V4 split probe | Native process exited zero | Signed M06 execution with module bootstrap and `legacy-task-v1`; not ordinary Node genesis. |
| Retained V4 split integration test | 1 native test passed, 12.66 seconds | Source `819`; ordinary Node provides genesis, followed by two alternative continuous signed M06 executions through height 76. |
| Independent split receipt check | Both recorded native receipts recompute | Full-model arithmetic, empirical records, allocation and claims, 46 Ed25519 envelopes, source reservations, and charged fixture-account fees. |
| Independent checker mutation controls | 6 unique mutation cases reject | Changed signature, complete model, claim, source reservation, account balance, and removed reveal. Repeats across receipts do not create additional independent definitions. |

The [legacy output](legacy-revision3/stderr.txt) retains the native/reference
counterexample. It establishes producer ordering influence under revision3, not
nondeterministic execution of one fixed ordered block.

The [complete-roster output](complete-roster/stdout.txt.gz) records all eight test
names. The strengthened existing entry
`every_arrival_order_closes_identically_and_missing_is_abort` executes all six
commit orders independently of all six reveal orders at 1/2/4/8 workers. It checks
complete State and root equality, not just a scalar score. Each omitted evaluator
aborts closure; two fast scores of 100 cannot suppress the absent score of 10.
This is an execution property of the declared development roster, not a guarantee
of independent evaluators, network delivery or public service availability.

The [Node-genesis command receipt](node-genesis-split/command-receipt.json) records
both source commits as `819`, both worktree statuses as clean, the exact Cargo
arguments, the selected environment and exit zero. The complete command, including
compilation, took 70.48314002499956 seconds. The test itself took 12.66 seconds;
these are separate quantities. The first complete-roster build took 32m 49s.
These timings are not a hardware or throughput qualification.

## The admitted V4 split

The [full native record](node-genesis-split/native.json) retains the original signed
inputs, complete model bytes, publication and actual claim records, source quotas,
account balances and final roots. Its SHA-256 is
`07c11a04880eab6303a66000d23082748a8f8568f8e1defe92d91c0a8b30db40`.
The [independent result](node-genesis-split/independent.json) binds that digest.

Both alternatives start from the same ordinary Node genesis state. The profiles
are `native-public-evaluation-dev-v1`,
`consensus-maintenance-continuity-dev-v1` and
`linear-factor-composition-dev-v4`. The Node is then closed; the assertions execute
M06 directly at every height from 1 through 76. **This test does not exercise
ordinary Node submission, PNW1 block verification or independent History
confirmation.** The native record explicitly leaves all three flags false.

The 25 rows are already public historical fixture data. Models `A` and `B` score
24 and 23 correct rows, and their complete sum scores 25. Keep the same author 2
contribution `B`, the actual parent and the complete bundle bytes. Replace author
0's component `A` with `(A + Z, -Z)`, submitted by authors 0 and 1. These two
admitted keys already map to the same installed source. `Z` changes only two
expert-zero class-bias coefficients by +1000 and -1000.

| Quantity | Original `(A, B)` | Split `(A + Z, -Z, B)` |
| --- | --- | --- |
| Individual correct rows | 24, 23 | 2, 20, 23 |
| Correct rows after each individual omission | 23, 24 | 20, 2, 24 |
| Native allocation weights | 80000, 40000 | 200000, 920000, 40000 |
| Actual payments | 66666, 33333 | 17241, 79310, 3448 |
| Aggregate payment to authors 0/1's source | 66666 | 96551 |
| All transaction fees charged to accounts 0/1 | 6615 | 9686 |
| Combined account increase after those fees | 60051 | 86865 |
| Source component intakes | 1 | 2 |
| Total claimed / rounding dust | 99999 / 1 | 99999 / 1 |

The payment increase is 29885; the additional charged fees are 3071; the combined
account increase therefore differs by **26814 development ledger units**. This is
not a full profit estimate: real-world training, search, evaluation, serving and
operating costs are unmeasured. Both alternatives have exactly one unit of dust,
so the change is not a rounding extraction.

Every required exact-zero-subset check passes: one for the baseline and four for
the split. `(A + Z) + (-Z) = A` is nonzero. Removing `-Z` exposes the damaging shift
in `A + Z`, giving the canceling `-Z` component the inflated weight 920000. The
full model is unchanged while the decomposition changes measured individual
omissions. The fixture preserves this admitted result rather than weakening the
native checker or changing the reward semantics.

The unchanged source limits remain enforced: 2 of 4 intakes and 96551 of 100000
reserved units. Author 3 signs and funds the 100000-unit release. The construction
requires public-row knowledge, control of the two already admitted same-source
keys, the unchanged `B`, a complete truthful evaluator round and an authorized
publisher accepting the assembly. It does not demonstrate a cap bypass, signature
forgery, involuntary payer debit, admission of arbitrary new identities or discovery
of hidden common controllers.

A fresh successor could close this specific known-source repartitioning gap by
aggregating complete parent-relative **deltas before computing source omission**.
Summing per-component weights after ablation does not close the gap. In this
fixture, source-level omission would yield weights 80000 and 40000 in both cases.
That is a derived repair condition, not an implemented successor result. Native
integer checks, complete derivation, authorized source-level payee/allocation,
finite funding, caps and source-level rounding must also be specified, with a
fresh profile and signed/stored namespaces. Unknown shared controllers, coalitions,
Shapley fairness and prospective data remain separate unresolved obligations.

V4's 25/25 saturation limit is unchanged. The current base also contains revision16
model evolution V5 and owner-pinned task-window loading. This record does not
mislabel every later model profile as the fixed 25-row V4 profile, or promote the
controlled V5 window fixtures into independent prospective evaluation.

## Independent checks and their limits

The [checker](reproduce/verify_incentive_split_receipt.py) uses the existing
independent Python composition oracle to recompute full models, exact subsets,
empirical score/digest records, allocation roots, claims, source reservations and
dust. It independently verifies every retained Ed25519 envelope, commit/reveal
binding and eligible-roster membership, then accounts for all fees charged to the
two source accounts and their observed balance changes.

The [mutation driver](reproduce/check_receipt_mutations.py) first verifies the
positive receipt, then requires rejection of each modified copy. The
[Node-genesis controls](node-genesis-split/mutations.json) retain the actual refusal
classes. Removing a reveal is caught by the resulting nonce inconsistency in this
transcript; that particular mutation does not alone prove every possible missing
reveal encoding is handled.

This layer checks retained inputs and observed outcomes. It does not independently
replay every M06 state transition, prove ILF2 witness soundness, certify independent
operators, establish training provenance, verify a PNW1 chain or confer public
economic qualification. The same scope applies to the separate
[module-bootstrap record](module-bootstrap/native.json), whose initialization and
legacy task profile must not be conflated with ordinary Node genesis.

From a checkout containing these files:

```sh
python3 evidence/chain-incentive-counterexamples-20261112/reproduce/verify_incentive_split_receipt.py \
  --repo . --receipt evidence/chain-incentive-counterexamples-20261112/node-genesis-split/native.json
python3 evidence/chain-incentive-counterexamples-20261112/reproduce/check_receipt_mutations.py \
  --repo . --receipt evidence/chain-incentive-counterexamples-20261112/node-genesis-split/native.json
```

A fresh native run uses the existing declared entry:

```sh
bash scripts/project-preflight.sh
cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --test model_composition_v4 \
  same_full_bundle_admits_split_reward_redistribution_with_known_aliases \
  -- --exact --nocapture
```

The archived module probe contains its original absolute include path and linked
rlib hashes. It is preserved as original source, not presented as a portable Cargo
entry. The retained integration test above is the portable native replay path.

## Source, preparation failures and unknown work

The original local source observations cover 4945 tracked files under
`trillionnium`, `config`, `formal`, `scripts`, `docs` and `.github`, plus
`AGENTS.md`, `PROJECT_BOUNDARY.json` and `PROJECT_ID`. They explicitly exclude
`evidence` and other top-level paths; they are **not a complete-worktree claim**.
The [before](source/before-public-evaluation.json) and
[after](source/after-public-evaluation.json) observations on `3b97` match exactly,
with zero missing or mismatching files. The [pre-split observation](source/before-split.json)
and [post-restoration observation](source/after-cloud-restoration.json) likewise
match the `819` source slice. The later observation records the restored source;
it does not turn interrupted commands into completed tests.

The default-feature Node build retained this warning:
`trnm SQLite I/O boundary UNQUALIFIED: RUSTC must be absolute`.
The optional bounded SQLite interface was not qualified. The crate explicitly
permits an ordinary/default Node build in that state, and this incentive campaign
makes no bounded SQLite claim. Toolchain and selected artifact details remain in
[native-build](native-build/selected-artifacts.json).

Before the cloud interruption, a further full Node V4/public-evaluation invocation,
a repeated source-integrity invocation and a Cargo metadata/inventory/formatting
sequence were attempted. Their terminal receipts were not recovered; the retained
full-suite streams and metadata output are empty, and the V4 vector directory is
empty. [The unknown record](unfinished/observations.json) preserves these facts.
They are not counted as passes or protocol failures. Strict Clippy, the remaining
native M06 quorum/evolution/arithmetic suites and the thirteen-file native V4
comparison were not completed by this evidence-only continuation. No native work
was restarted in the restored cloud to obscure the interrupted observations.

Original successful raw files were recovered after the cloud environment became
available again. During the outage, the source's three changed blobs, all necessary
trees and both commits were also reconstructed from original tool text and
immutable base objects; every Git SHA matched the previously observed identities.
Recovery preserved the original `819` identity. The raw native record's SHA-256
above also matches its pre-outage observation. The resumed raw files, not a
recreated execution log, are retained here.

AI395 setup is recorded separately from native acceptance. The initial setup
[stderr](setup/ai395-initial.stderr.txt) shows preflight exit 2 because the new
`verify/` branch prefix was outside the existing allowlist; the Python wrapper
[exited 1](setup/ai395-initial.status.json). No build was started. A later authorized
continuation renamed only that new branch to the already allowed `fix/` prefix;
no policy rule changed. Its [output](setup/ai395-continuation.stdout.txt) and
[terminal status](setup/ai395-continuation.status.json) show preflight PASS and
all 28325 tracked files / 2578722854 bytes physically matching the C5 Git blobs,
including historical evidence. The borrowed dirty checkout's HEAD and status
fingerprint remained unchanged. This is C5 environment preparation, not validation
of a later combined candidate. The full manifest is retained on that host under
`trillionnium/target/chain-system-security-receipts/preparation-c5.json`.

Only this task's completed incremental caches were removed under storage pressure.
The standalone probe ELF was compressed losslessly and its decompressed SHA-256
checked; [the compression record](setup/lossless-probe-compression.json) preserves
both identities. The compressed executable remains a local retained build artifact
and is not included in this Git evidence directory. No other worktree or live
build target was cleaned. The source preparation failure, original compiler
warning, observer timeout and unknown test attempts remain visible.
