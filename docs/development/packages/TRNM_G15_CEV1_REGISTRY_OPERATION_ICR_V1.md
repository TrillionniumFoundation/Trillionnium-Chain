# G1.5 CEV1 operation-registry semantic ICR v1

Status: **proposed / implemented-candidate / BLOCKED_UPSTREAM**

This typed handoff records the A08 correction required after the original
registry projection was found to assign different bodies to the canonical
`OperationPayloadV1` kinds.  It is a candidate interface request and does not
promote protocol, activation, implementation, or production truth.

```yaml
request_id: G15-ICR-OPERATION-MAPPING-V1
requester_agent: A08
requester_package: G15_CEV1_REGISTRY_SPEC_V1
owner_agent: A08
owner_package: G15_CEV1_REGISTRY_SPEC_V1
owner_authority: protocol-authority
created_at: 2026-08-29
status: implemented-candidate
base_ref: feature/chain-a08-g15-registry-parity-v4-20260829
base_commit: 7d9a17abb727950f278235dce817df29e97fea19
base_tree: 00a9de9534860abdccc2aeb31307810897330c4c
current_interface: operation-registry-v1.json (pre-correction PR27 projection)
current_interface_version: trnm-cev1-operation-registry-v1
current_interface_digest_sha256: ceccd5596e893e150e9e11d895ceed28dcfed421f0683891b2dfd2a558b0c028
proposed_interface: operation-registry-v1.json (canonical body projection)
proposed_interface_version: trnm-cev1-operation-registry-v1
proposed_interface_digest_sha256: ec856f6c02b26137200c9353cadaeac9cb3c4c417f2b8f9844baa81041efecf7
serialization: canonical committed UTF-8 JSON bytes; no wire activation
```

## Requested interface

Bind every kind `0..29` to the exact body/object identifier in document 08's
`OperationPayloadV1` table.  The registry keeps a short display `name` for
review ergonomics and adds the exact `body_type`; consumers MUST bind and
compare `body_type`, not infer semantics from the display label.  The
candidate checker also compares the exact plane, status, authority slug, and
nonce-lane role for every row.

The authority slug is the closed `OperationLimitV1.outer_authority_mode`
mapping: `existing-agent=0`, `existing-or-self-origin=1`,
`permissionless-trigger=2`,
`externally-signed-object-submitted-by-agent=3`, and `action-dependent=4`.
Kinds 18, 23 `CloseExpired`, 26, and 28 `GarbageCollect` are permissionless
branches; their outer sender still pays/consumes the ordinary transaction
nonce but gains no lifecycle authority.  Kinds 21, 24, 25, and 27 carry inner
verifier/bilateral/evidence signatures; those signatures never substitute for
the outer submitter authorization.  Kinds 20 and 27 remain explicit disabled
profile rows with `ERR_OPERATION_DISABLED`; all registry `enabled` bits and
`global_activation` remain false.

## Semantic vectors and retained mutants

Required positive coverage is one exact row for each kind `0..29`, including
the two disabled profile rows and kind 29's ordinary candidate assignment.
Required negative coverage includes:

- short name, exact `body_type`, plane, authority, and nonce-lane drift;
- status/error drift for kinds 20 and 27;
- any row enabling or top-level activation;
- duplicate/missing/reordered kind slots and malformed/unknown fields;
- canonical object/catalog projection, domains, limits, and profile fallback.

The A08 retained harness implements these as 17 fail-closed cases in
`cev1-registry-mutants-v1.json`; a mutant is accepted only when the checker
rejects it with the expected invariant message.

## Compatibility and invalidation

Changing a kind/body/plane/authority/nonce assignment changes the accepted
operation interpretation and therefore invalidates the old A09 independent
parser, A10 W0–W7 trace inventory, and all downstream A11–A17/G2 vectors,
fixtures, manifests, and benchmark evidence. Downstream agents MUST replay
from this proposed digest and record their own exact base/tree; they MUST NOT
silently normalize the old mapping.

## Safety and authority analysis

```text
new_authority_created = false
production_reachability_changed = false
signing_or_settlement_authority_changed = false
serialization_boundary_changed = true  # candidate mapping only; no activation
normative_freeze = false
global_activation = false
```

The serialization-boundary flag is why independent protocol-owner review is
required. A08 has not changed numbered protocol text, status truth, activation
truth, or production code.

## Review and handoff decision

```yaml
owner_decision: pending protocol-authority review
independent_reviewer: required (not A08)
accepted_interface_version: pending
accepted_interface_digest: pending
source_commit: see closing evidence (enclosing correction commit)
source_tree: see closing evidence (enclosing correction tree)
downstream_gate: BLOCKED_UPSTREAM until A08 review and independent A09 replay
```

The source commit/tree and proposed digest MUST be revalidated after replay on
the final A00 control head. This document is the handoff; it is not an A00 ICR
registry entry and must not be treated as acceptance.
