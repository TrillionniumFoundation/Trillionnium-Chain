---
status: canonical
owner: Trillionnium Chain maintainers
last_verified: 2026-09-04
applies_to: main@b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9
---

# Documentation standard

## Purpose

Documentation is part of the protocol and operational control surface. It must
state what the repository actually implements, identify where evidence applies,
and prevent legacy or experimental paths from being mistaken for production.

## Required module contract

Every member of `trillionnium/Cargo.toml` must contain `README.md` with:

1. metadata: `status`, `owner`, `last_verified`, and `applies_to`;
2. responsibilities;
3. non-responsibilities and production boundary;
4. source layout;
5. required invariants;
6. build and test commands;
7. failure, recovery, and observability rules;
8. change rules;
9. known gaps or activation conditions;
10. references to architecture and release truth sources.

A module document is not a marketing page. It must preserve open gaps and say
when tests are legacy, local, single-host, mock, or research evidence.

## Status vocabulary

- `canonical-consensus-critical`
- `canonical-production-candidate`
- `supported-consumer-boundary`
- `operator-read-surface`
- `client-integration`
- `client-operator-tool`
- `legacy-frozen`
- `legacy-compatibility`
- `legacy-research`
- `legacy-experimental`
- `legacy-shared-types`
- `test-only`
- `deferred-research`
- `internal-research`

Changing status requires updating the module catalog and attaching the relevant
implementation and acceptance evidence.

## Normative language

- **MUST / MUST NOT**: release- or consensus-blocking requirement.
- **SHOULD / SHOULD NOT**: expected default; exceptions require rationale.
- **MAY**: permitted option without a readiness claim.

## Evidence binding

Any performance, recovery, security, compatibility, or readiness claim must
record:

- repository URL and exact commit;
- dirty/clean state where applicable;
- command and complete relevant configuration;
- operating system, architecture, toolchain, and hardware class;
- start/end time and result;
- artifact path plus digest;
- whether the run was unit, process, loopback, single-host, multi-host,
  public-testnet, or mainnet;
- known exclusions and residual risk.

A later document may supersede an earlier one only through explicit metadata or
a canonical index update.

## Protocol-change checklist

A consensus-visible change must update, in one pull request:

- canonical types and validation;
- deterministic runtime transition;
- application routing and unknown-version rejection;
- stable error/event/schema versions;
- positive, negative, boundary, replay, and failure-immutability tests;
- golden vectors and fuzz seeds where encoding changes;
- storage/snapshot/upgrade compatibility;
- module documentation and maturity catalog;
- release/readiness status when evidence materially changes.

## Link and freshness rules

Canonical indexes may link only to files present in the same tree. References to
removed documents must be deleted or clearly placed in an archive record.
Module metadata is reviewed on every behavior change and at least once per
release cycle.

Run:

```bash
python3 scripts/ci/check_documentation_integrity.py
```

The gate rejects an empty root README, missing required headings, missing module
READMEs, incomplete metadata, missing catalog entries, and broken relative links
within canonical entrypoints.
