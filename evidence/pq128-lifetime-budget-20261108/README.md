# PQ128 lifetime budget source validation — 2026-11-08

Disposition: **HOLD / NO-GO** for actual whole-chain PQ128, production consensus
and deployment. This change implements the research budget register, exact
arithmetic, negative controls and claim/CI integration. It does not instantiate
the missing cryptographic or quantum-work proofs.

Base: PQ integration candidate
`12e510b211110d93d9ead07e02c07a1eecc28ae9` (PR #723).
See the [security contract](../../docs/security/PQ128_LIFETIME_BUDGET_V1.md),
[actual unknown register](../../config/pon/pq128-lifetime-budget-v1.json),
[separate arithmetic example](../../config/pon/pq128-lifetime-example-v1.json),
and [checker](../../scripts/ci/pq_lifetime_budget.py).

## Observations

The actual register has eight unknown event terms, four unknown shared-public-
primitive query budgets and nine unmet conditions. Its derived model sum and
actual lifetime bound are both null. The separate example evaluates exactly to
`8 * 2^32 * 2^-163 = 2^-128`, but has no theorem or actual resource certificate.
All qualification and activation outputs remain false in both cases.

| Source suite | Observed result |
| --- | --- |
| Budget arithmetic, strict inputs, lifecycle scopes, real source/CLI refusal | 45 passed |
| Whole-chain claim guard, including actual filesystem races and conflicting claims | 46 passed |
| Hosted-CI structure and mandatory command refusal | 105 passed |
| PQ integration/source-integrity controls | 55 passed |
| Exact PQ corpus | 718 source blobs checked; 637 mandatory paths; HOLD_NO_GO |

Suite counts are execution counts. Shared controls may occur in more than one
suite; these rows are not summed into a distinct-control or security-success
count. The command record and complete retained stdout/stderr identify the
final observed source and results.

The original claim guard permitted newly introduced contradictory fields such
as `whole_chain_pq128_qualified=true` and a numerical
`whole_chain_failure_probability` while still emitting its own false/HOLD
outputs. This was a declaration-coverage gap, not a demonstrated production
authorization bypass. The added explicit reserved-field checks refuse those
claims, including nested occurrences in the configuration objects read.
The current research register also cannot be replaced by the arithmetic example.

## Limits and failed preparation observations

The initial complete local checkout failed because the shared Git object store
lacked historical evidence blobs. Work proceeded in an isolated sparse worktree
without changing other worktrees. All 25 evidence files required by the existing
source corpus were restored from verified local baseline blobs. Further local
Markdown targets and fifteen missing historical text/JSON blobs were recovered
from the canonical GitHub commit and checked against their exact Git object IDs.
This is restoration of baseline bytes, not new security evidence or new native
execution.

The repository-wide link check first refused missing `evidence/pon-v1/README.md`
and later refused further unavailable historical evidence targets. It is retained
as a failed complete-repository check, not silently narrowed into a full pass.
Changed-document link checks and the 718-blob source gate have their own scopes.

No Rust implementation, Cargo manifest, lockfile or formal runtime file changes
in this patch. The current executor has no `cargo` executable; fresh Cargo graph,
formatting, native tests and strict Clippy are not claimed. Earlier native
failures and all existing production qualification gates remain in force.
The PR is a draft pending the repository's ordinary full checks and review.

## Evidence interpretation

`commands.json` records actual subprocess arguments, timing, completion/launch
errors and log hashes. `sources-before.json` and `sources-after.json` bind the
changed implementation/configuration/document files; unchanged runtime and
formal tree identities are recorded separately. This records local source
validation, not independent cryptographic acceptance or a deployed evaluation.

The schema deliberately offers no promotion switch. Whole-chain event coverage,
shared-model replacement errors, exact theorem applicability, preprocessing and
advice, real adversary resource caps and cross-owner assumptions remain open.
