# G2.0 W0-W7 traceability and code generation v1

Status: **MODULE_CLOSED_CANDIDATE for trace generation / G2.0 exit blocked**

Package ID: `G20_W0_W7_TRACEABILITY_V1`
Agent: `A10`
Upstream is pinned in `docs/evidence/g2.0/g20-source-manifest-v1.json` by
commit, Git tree, raw blob SHA-256 and parser source.  The checked snapshot is
currently marked `upstream-pending`; it must be refreshed when A08's semantic
correction and A09's strict parser head are stable.

## Objective

Generate one deterministic trace row for each operation kind `0..29` and make missing links visible as blockers rather than silently treating local kernels as integrated protocol authority.

## Link meanings

- W0: closed operation slot, schema/domain/bounds/error.
- W1: authorized `AgentTransactionV1` or explicitly typed system authority.
- W2: transaction batch/artifact DA and exact content root.
- W3: proposal/QC/finality binding.
- W4: deterministic execution receipt and application JMT root.
- W5: result/profile/challenge decision.
- W6: settlement intent/receipt and conservation.
- W7: RPC/WS/SDK/indexer/light-client projection.

## Invariants

1. Exactly 30 rows are generated from the pinned A08 registry.
2. Required links are derived by closed plane policy, not by success claims.
3. Evidence starts `null`; a local SQLite root, fixture, composite root, or transport response cannot fill an authority link.
4. Every row whose source status is `disabled` terminates at W0 and carries
   `ERR_OPERATION_DISABLED`; no kind number is assumed to be the sentinel.
5. `g2_0_complete` remains false until all applicable links for every enabled kind contain accepted evidence and two independent parser results.
6. Unknown planes fail generation.

## Commands

```bash
bash scripts/ci/check_w0_w7_traceability_v1.sh
```

The gate rejects dirty worktrees, missing/mismatched source tuples, raw blob
or canonical digest drift, duplicate/trailing/non-finite JSON, weak types,
incomplete 30-row metadata, and parser evidence without explicit IDs.  It
writes deterministic candidate artifacts (never a `/tmp`-only pass):

- `docs/evidence/g2.0/g20-w0-w7-closure-v1.json`
- `docs/evidence/g2.0/g20-evidence-index-v1.json`

The retained regression harness exercises the same negative classes without
touching the committed registry.

## Exit boundary

This package closes the generator and structural trace inventory only. The produced rows deliberately expose null schema hashes, access sets, owners and evidence until their owning packages deliver them. G2.0 promotion is `BLOCKED_UPSTREAM`.

## Non-claims

```text
g2_0_complete=false
wire_conformance_complete=false
rpc_sdk_complete=false
light_client_complete=false
node_support=false
production_candidate=false
```
