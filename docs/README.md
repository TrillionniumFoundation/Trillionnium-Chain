# Trillionnium Chain documentation

The repository has one active development direction:

- **Development plan:** `development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`
- **Machine truth:** `../config/consensus-mainline.json`
- **Release projection:** `../RELEASE_READINESS.md`
- **Module technical reference:** `modules/TRNM_MODULE_TECHNICAL_REFERENCE_V1.md`
- **Machine module coverage:** `../config/module-coverage-v1.toml`

`docs/development/` contains the plan and compact machine companions only. Git
history is the development-document archive; retired history directories,
dated delivery boards, per-agent prompt packs, package roadmaps, sprint plans,
and continuation notes are prohibited from active documentation.

Current domain authorities are organized as follows:

- `modules/` — stable M00–M17 technical contracts, boundaries, failure/recovery,
  security, verification and SLO profiles; never a second roadmap;
- `architecture/` — active architecture decisions and boundaries;
- `protocol/` — versioned protocol specifications, schemas, vectors, parameters,
  manifests, and implementation-gap registers;
- `evidence/` — immutable evidence schemas, submissions, and source-bound records;
- `runbooks/` and `OPERATIONS.md` — operator procedures and candidate boundaries;
- `schemas/` — machine-readable repository and evidence schemas;
- `audits/` — source-bound audit records, never active roadmaps;
- `bench/` and `performance/` — source-bound measurements and benchmark contracts,
  never release authority.

A document outside the canonical development plan may define its own domain
contract, but it may not assign future work, alter gate order, promote machine
truth, or become an alternate navigation entry for development. A module is not
implemented merely because its technical reference exists; implementation and
promotion require exact-source tests, accepted evidence, protected review and,
where applicable, independent external evidence and signed governance.
