# web4-frontend

Web4 is the non-authoritative Next.js client surface for Trillionnium Chain.

Current runtime semantics are deliberately narrow:

- the default path is a **read-only API client**;
- local snapshot fallback is available only with explicit `?mode=mock`;
- no transaction-signing or write route is provided;
- a Web4 gate cannot promote repository release truth.

## Documentation

Use the checked-in live documentation only:

- [documentation index](./docs/README.md);
- [read-only API contract](./docs/api-contract.md);
- [developer guide](./docs/developer-guide.md);
- [testing and CI](./docs/testing-ci.md);
- [operations runbook](./docs/operations-runbook.md);
- [release checklist](./docs/release-checklist.md);
- [repository release projection](../RELEASE_READINESS.md);
- [canonical Chain development plan](../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

Historical scorecards and removed archive paths are not live documentation
authorities and must not be linked as if they were present in the current tree.

## Local development

```bash
npm ci
npm run dev
```

The default development URL is `http://localhost:3000`.

Copy the environment template when local overrides are needed:

```bash
cp .env.example .env.local
```

The supported variables and response contracts are defined in
[`docs/api-contract.md`](./docs/api-contract.md).

## Quality gates

```bash
npm run lint
npm run typecheck
npm run test
npm run test:contract
npm run build
```

The aggregate gates are:

```bash
npm run ci:check
CI_RUN_E2E=1 npm run ci:check
npm run release:preflight
npm run release:ready
```

`release:ready` is a Web4 package gate only. Repository-wide readiness remains
the explicit NO-GO/GO value in [`RELEASE_READINESS.md`](../RELEASE_READINESS.md).

## Required next integration

A production-capable client still requires:

- generated types and clients from the canonical protocol registries;
- a transaction builder and an isolated signer boundary;
- M05 admission and authorization rather than direct backend mutation;
- finality/proof/freshness metadata on every canonical response;
- explicit stale-indexer and degraded-read UX;
- real-node transaction-to-finality-to-proof end-to-end tests;
- API version migration and backward-compatibility evidence.

Until those items close, describe Web4 as a read-only observation client with an
explicit mock mode, not as a production wallet or write-enabled chain frontend.
