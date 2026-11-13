# Source-level incentive V6: retained finite-profile observations

The V6 candidate was tested at the fixed source commit
[`214e2224fd4d18134aa9b50dc1467041651112eb`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/tree/214e2224fd4d18134aa9b50dc1467041651112eb),
tree `b4b02cca0aff2af5603618ffea510743d54a2f2d`. Its second validation run
completed **19 of 19 commands successfully**, with a clean tracked checkout
after the run. The archived authoritative process status records successful
termination, exit code 0, complete durable output, and no cancellation or
timeout. The four native V6 tests passed, and the direct native invocation
was `PINNED_AND_OBSERVED` against executable SHA256
`f374c315f104569850e7164af5627abfb86c5ee33efd05c2241d8b5a578bab7b`.

This directory is a later evidence and documentation child. Its native
execution receipts remain attached to that tested source commit. Adding this
directory and the plan conclusion does not constitute native execution of the
evidence child. See [summary.json](summary.json), the raw receipts below, and
[source-protection.json](source-protection.json).

## Observed source split, alias, and order invariance

The registered `linear-source-composition-dev-v6` profile aggregates complete
parent-relative updates with checked integer arithmetic before source
valuation, nonnegative clipping, the source budget floor and cap. A source's
entitlement is then distributed among the signed component owners. Both
representations must pass admission, and the parent, complete source updates,
source set, evaluation plan, budget and frozen source caps must match.

The [native invariance observation](native-invariance.json) retains full ILM2
model bytes, component manifests, complete signed transactions, source records,
payment records and account observations for these four finite cases:

| Representation | Known source gross reward | Other source gross reward | Unallocated release budget | Native reported net account change after its own fees |
| --- | ---: | ---: | ---: | ---: |
| Original | 66,666 | 33,333 | 1 | 60,051 |
| Aliased payout owner | 66,666 | 33,333 | 1 | 60,051 |
| Split into positive and negative components | 66,666 | 33,333 | 1 | 56,980 |
| Permuted split components | 66,666 | 33,333 | 1 | 56,980 |

The 1 unit is the budget residual still present in the release escrow at the
observed height. The existing expiry rule governs its eventual return; the
observation does **not** show that refund already credited to an account.
Fees are separate from entitlement. Splitting consumes extra operations and
fees in this fixture, so its net account change is lower despite the equal
gross source reward. The independent reader does not replay these account
balances or independently establish the reported net changes.

All four retained complete models are identical. On the 25 frozen public
historical rows, the parent scores 3; the frozen controls score 18, 19, 19 and
19; the full model scores 25. The two source-alone scores are 24 and 23. The
corresponding complete-source omissions score 23 and 24, yielding source
weights 80,000 and 40,000. Every variant has source game digest
`3a59900aa1b26ff93376dc4f852c59a9677c08a07a38dfe5cfdb2813be4634f2`.
These are public historical observations, not a fresh independent holdout.

The original V4 counterexample remains unchanged at
[`node-genesis-split/native.json`](../chain-incentive-counterexamples-20261112/node-genesis-split/native.json).
It records the earlier increase from 60,051 to 86,865. A copy of those exact
historical bytes is retained in the raw archive. V4's old behavior and failure
evidence have not been replaced with V6 results.

## Two native scopes

The four representation cases execute consecutive signed M06 commands through
heights 1 to 76, starting from ordinary `Node::open` genesis state. Their own
receipt explicitly sets `PNW1_chain_verified` and
`ordinary_Node_submission_verified` to false. They do not establish that the
four cases were submitted as four packet chains through the network ingress.

The separate [owner observation](native-owner.json) records **98 ordinary node
packets**, source payment, duplicate-claim handling, reorganization and
persistent-state reopen equality. It records a paid source total of 100,000,
source reservation 0 after reorganization, and both reopen equality checks as
true. This test supplies the packet/state-machine scope; it does not extend
the four representation observations into a larger network or market trial.

The four passing native tests also retain the signed marker and packaging
failure cases and the two-generation replay with the actual nonzero parent.
See the native raw log and receipt for the individual test names and contexts.

## Independent recomputation and its limits

[independent-readback.json](independent-readback.json) is the exact second-run
reader output. The reader reports
`PASS_FINITE_NATIVE_RECEIPT_RECOMPUTATION`, and its **11 synthetic self-tests**
pass. It reconstructs the complete integer models and source deltas; recomputes
inference, source-alone and omission values, weights, source entitlements and
owner allocation; parses retained PNX1 senders and factor submissions;
rederives contribution and update identifiers; checks the signed tag-8
component manifest; and recomputes the V6 allocation root, release identifier,
source game digest and stored record digest. Fixture author ordinals are not
used as author identities.

This reader does not independently verify cryptographic signatures, source
registration truth, historical funding or reservation authority, ledger roots,
actual account-payment replay, or market behavior. Its source-cap check verifies
the configured maximum and reported arithmetic, not an independent replay of
the prepublication reservation state. The native observer also explicitly
declines build-provenance, descendant execution, whole-lifetime image, loaded
memory and dynamic-library closure verification. These limitations remain in
the original JSON; no qualification fields are promoted here.

## Validation results bound to the tested source

| Second-run command or suite | Actual retained result |
| --- | --- |
| Native V6 suite | 4 passed; 0 failed |
| MVCC fee library | 164 passed; 9 ignored |
| Retained native V4 suite | 5 passed; 0 failed |
| M10 task kernel | 35 passed; 0 failed |
| Node error registry suite | 11 passed; 1,333 filtered out |
| Independent reader self-tests | 11 passed |
| All-feature strict Clippy | Passed with `-D warnings` |
| Source identity, formatting and both locked metadata checks | Passed |
| Source inventory, authority negatives/register, repository links, source corpus, integrity negatives and arithmetic self-tests | Passed |

All 19 original command receipts and logs are in
`raw-observations.tar.xz` under `source-2/`. The row-by-row command list,
durations, exit codes and raw-log hashes are preserved in
[source-validation-summary-2.json](source-validation-summary-2.json).
The error registry contains 18 new source-related code strings; **11** is the
actual filtered suite's test count, not the number of new strings.

## Failures and earlier observations retained

The first exact-source run tested
[`8cb8b743bccd93a5fac49a072990d18e0d4b4a21`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/tree/8cb8b743bccd93a5fac49a072990d18e0d4b4a21).
Fourteen of its 15 commands succeeded. Its native suite reported **3 passed and
1 failed**, because an owner-test fixture attempted to read a contribution
after publication had pruned it. The second source fixes that fixture's
observation order and records an actual new native execution. Both complete
drivers, summaries, all 15 first-run receipts/logs and all 19 second-run
receipts/logs are retained. The preliminary uncommitted node-test compile
failure (`E0603`, private `canonical` module) also remains; it is not relabeled
as native execution.

The first independent reader used the old `release` domain and refused the
retained V6 receipt. Its failed source and report are archived alongside the
corrected `source-release-v6` reader, the second attempt's successful report,
the source-weight and sender tamper controls, and the exact legacy-domain
negative script and report. The original reader manifest is retained without
rewriting its paths or hashes. Its historical research-contract entry is read
from its original first-source Git blob when the current file differs.

The unchanged prior authority reader's real `source lock hash mismatch`
refusal, reviewed continuation patch, prior files, apply receipts and
pre-integration checks are also included. The authority register remains
`HOLD`; its scope and false qualification fields remain unchanged.

## Archive layout and source protection

The deterministic XZ-compressed tar archive preserves every raw input byte,
including log whitespace. Its members have fixed metadata and are listed with
original location, size, SHA256 and SHA512 in
[artifact-manifest.json](artifact-manifest.json). The browser-friendly JSON
files are either unchanged raw JSON or exact marker payloads extracted from
the second native log. The original full logs remain the authoritative context
for those extracts. [summary.json](summary.json) contains derived navigation
and assertions, explicitly linked to those observations.

`source-protection.json` lists every tracked path under `trillionnium/`,
`formal/`, `scripts/` and `config/` at the tested source, with Git blob identity,
byte count and SHA256. The evidence child may only add this evidence directory,
prepend the sole development plan, and change the existing plan entry in
`config/pon/pq-cross-branch-corpus-v1.json`'s `pinned_blobs` object. That one
plan-pin field is the only protected-root exception. No source corpus route,
qualification flag, other pin or tested implementation file may change.

The included archiver can verify the final worktree or committed child:

```sh
python3 evidence/chain-source-incentive-v6-20261112/archive_driver.py verify \
  --root . --target HEAD \
  --report /tmp/source-incentive-evidence-child-verification.json
```

Use `--target WORKTREE` before committing. The verification checks the full
protected path set, source modes and blob identities, the sole corpus-pin
exception and the allowed evidence-child change set. Its report names the
tested source separately from the observed child. It performs no native test
and makes no new native-execution claim.

## Guarantee boundary

This evidence closes the retained known-source packaging counterexample
within the registered finite integer profile and the stated fixed-game and
admission conditions. It does not prove arbitrary Cell semantic equivalence,
floating-point or LoRA-factor equivalence, unknown common-control discovery,
unrestricted Sybil resistance, collusion resistance, truthful bidding or global
fairness. A raw semivalue's property is not transferred to the normalized
budget payment rule without a separate proof. Invalid source omissions or
source-alone counterfactuals remain insufficient evidence.

The collateral, concurrency, audit and randomness analyses remain scoped
models and threat descriptions. This archive grants no real-market economic
security qualification, production activation, universal fairness or
whole-chain post-quantum security claim. The preserved flags remain false.
