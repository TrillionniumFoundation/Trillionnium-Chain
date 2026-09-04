---
status: canonical
owner: Trillionnium Chain maintainers
last_verified: 2026-09-04
applies_to: repository
---

# Trillionnium Chain documentation center

This index is the live navigation layer. It deliberately separates normative
architecture/protocol material from operational procedures, release evidence,
and archived history.

## Truth-source order

1. [`../RELEASE_READINESS.md`](../RELEASE_READINESS.md) — current release and
   external-readiness decision.
2. [`architecture/TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md`](architecture/TRNM_CANONICAL_RUNTIME_FREEZE_2026-07-28.md)
   — binding production-candidate path and feature/runtime matrix.
3. [`MODULE_CATALOG.md`](MODULE_CATALOG.md) — active module maturity and
   documentation coverage.
4. Module-local `README.md` files — implementation responsibilities,
   non-responsibilities, invariants, and tests.
5. [`../OPERATIONS.md`](../OPERATIONS.md) and [`runbooks/README.md`](runbooks/README.md)
   — operator actions.
6. Dated reports, evidence packs, and `archive/` — scoped historical evidence,
   never the current global decision.

## Core indexes

- [Architecture](architecture/README.md)
- [Protocol](protocol/README.md)
- [Runbooks](runbooks/README.md)
- [Release and evidence](release/README.md)
- [Module catalog](MODULE_CATALOG.md)
- [Documentation standard](DOCUMENTATION_STANDARD.md)
- [Rust workspace](../trillionnium/README.md)
- [External contracts](../contracts/README.md)
- [Web4 frontend](../web4-frontend/docs/README.md)

## Boundary rules

- A capability is implemented only when it executes through its owning canonical
  path with reproducible evidence.
- Legacy, research, benchmark, mock, scaffold, or frontend behavior must retain
  those labels.
- Planning documents describe intended work; release evidence describes one
  bounded run; neither supersedes the readiness truth source.
- Broken links, empty entrypoints, missing module contracts, and missing metadata
  are CI failures.
