## Exact source tuple

- Base ref:
- Base commit:
- Base tree:
- Head commit:
- Head tree:
- Plan ID / SHA-256:
- Protocol manifest SHA-256:
- Cargo.lock SHA-256:

## Scope and authority

- Package / gate:
- Evidence scope: `crate | fixture | process | host | network | production`
- Authority: `candidate | simulation | normative | production`
- Changed safety invariants:
- Downstream invalidation set:

## Verification

- [ ] `repository-truth` completed successfully on the exact head.
- [ ] `rust-baseline` completed successfully on the exact head.
- [ ] Package-owned positive, negative, mutation, recovery, and replay tests ran.
- [ ] No skipped, stale-head, synthetic-merge, or queued run is cited as evidence.
- [ ] Generated files are reproducible and the worktree is clean after generation.
- [ ] Critical paths have a non-author review from their CODEOWNER.
- [ ] All production/readiness/activation claims are backed by accepted signed evidence.

## Explicit non-claims

List every gate, production, release, migration, benchmark, or activation claim that
remains false. A candidate PR must not promote machine truth merely because local
tests pass.

## Remaining blockers

For each blocker include owner, exact acceptance predicate, evidence output,
invalidation rule, and next executable action.
