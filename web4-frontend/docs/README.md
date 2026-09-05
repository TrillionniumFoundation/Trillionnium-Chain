# Web4 documentation

This directory is the live documentation entry for `web4-frontend`.

The current product boundary is:

```text
read-only query client
+ explicit ?mode=mock fallback
+ no write or signing path
+ no repository-level release authority
```

## Live documents

- [Developer guide](./developer-guide.md)
- [Read-only API contract](./api-contract.md)
- [Testing and CI](./testing-ci.md)
- [Operations runbook](./operations-runbook.md)
- [Release checklist](./release-checklist.md)

Repository-level sources:

- [Release readiness projection](../../RELEASE_READINESS.md)
- [Canonical development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
- [M00-M17 technical reference](../../docs/modules/TRNM_MODULE_TECHNICAL_REFERENCE_V1.md)
- [Repository documentation map](../../docs/README.md)

Removed archive paths, historical scorecards, and prior delivery boards are not
live navigation targets. Historical facts remain available through Git history
and immutable evidence, but they must not be used as current readiness authority.

## Interpretation rules

Use the documents above according to the question being answered:

| Question | Authority |
| --- | --- |
| Is the whole repository releasable? | `RELEASE_READINESS.md` |
| What does Web4 currently call? | `api-contract.md` and `lib/api-contract/` |
| How is Web4 built, tested, released, or rolled back? | `testing-ci.md`, `operations-runbook.md`, `release-checklist.md` |
| What work is next and which gates control promotion? | the canonical Chain development plan |
| Which module owns the client surface? | M14 in the technical reference and module coverage manifest |

A package-level Web4 PASS means that the frontend package gate passed on one
exact source. It does not mean that consensus, state sync, signer custody,
production transaction admission, or repository release gates are closed.

## Standard commands

```bash
npm ci
npm run dev
npm run lint
npm run typecheck
npm run test
npm run test:contract
CI_RUN_E2E=1 npm run ci:check
npm run release:preflight
npm run release:ready
```
