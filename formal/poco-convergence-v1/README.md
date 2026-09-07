# PCC1 abstract conformance examples

Scope: candidate contract tests only. No production consensus, signing, migration
or application authority. No complete formal verification claim.

From the repository root, with Python 3.10 or newer and no third-party packages:

```sh
python3 formal/poco-convergence-v1/check.py
```

This runs 40 baseline unit tests and ten retained unsafe/regression mutations.
An empty/incomplete test collection, skipped test, surviving mutant or missing
mutation anchor fails the command. Mutants are compiled and run only in temporary
directories. The source files are not changed. The command accesses no network,
repository credentials, validator key or production database.

The baseline alone is:

```sh
python3 -m unittest discover -s formal/poco-convergence-v1 -v
```

Covered examples are equal/unequal-weight quorum intersections, majority and
arbitrary-n threshold counterexamples, selected finality proof relationships,
context binding, signing-stage sequencing, exact retry and generation rejection,
aggregate resource and escrow conservation, nonce lanes, pinned result profile,
late results, repeated settlement, retained storage and bounded empty-block service.
A new ready event cannot overtake an older ready event merely by choosing a lower ID.

The retained liveness cases additionally recycle maximum-u128 principal through
refunds, admit more tasks than the lifetime slot count, enforce retention before
slot reuse, preserve archived-task replay protection and recover saturated diagnostics.
A cumulative refund diagnostic is an explicitly marked saturated lower bound,
not an asset or a replacement for exact settlement records. Active slots count
unsettled or retention-encumbered tasks, not already retired historical records.

The model assumes authentication/authorization where needed. It does not verify
signatures, proof computation, provider identity, real task dependencies, data
availability or a complete canonical codec. `check_finality_shape` is not a finality
verifier and `resolve(..., accepted)` is not a production result API. `reopen()`
copies abstract state; it is not a disk/HSM crash experiment. The simplified ledger
bounds active task responsibility but retains history in memory for replay checks;
it does not implement bounded production storage or authenticated archive pruning.

No model test executes `trnm-consensus-core`, its full safe-vote/TC/epoch transitions,
a live validator, network protocol or state synchronization. Physical durability,
cryptographic vectors, complete model checking, Rust integration, cross-language
clients, multi-host performance, migration and independent acceptance remain open.

The [protocol contract](../../docs/protocol/poco-convergence-v1/README.md) and its
AI/migration companions define the implementation target. Candidate status is
machine-readable in `config/poco-convergence-v1.json`. Passing these tests never
changes `config/consensus-mainline.json` or any production/release flag.
