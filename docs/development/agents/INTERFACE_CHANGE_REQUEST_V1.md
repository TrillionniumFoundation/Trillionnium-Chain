# TRNM Interface Change Request v1

Status: **template; required before crossing Agent ownership boundaries**

## Request

```text
request_id = ICR-<package>-<sequence>
requester_agent =
requester_package =
owner_agent =
owner_package =
created_at =
status = proposed
```

Allowed status values:

```text
proposed
needs-information
accepted-for-implementation
implemented-candidate
reviewed
rejected
superseded
invalidated
```

## Current authority

```text
base_ref =
base_commit =
base_tree =
current_interface =
current_interface_version =
current_interface_digest =
current_owner =
```

## Requested interface

Describe the smallest interface/capability change. Include:

- semantic version;
- canonical fields/bytes/domain;
- issuer and caller authority;
- ownership/linearity/non-Clone constraints;
- size/count/depth/signature/CPU/time bounds;
- exact errors;
- durability, response-loss and replay rules;
- compatibility and explicit rejection;
- positive and negative vectors;
- fault-injection hooks, if any.

## Rationale

Explain why the requester cannot close its package through the current frozen
interface. Convenience, test bypass or raw-field access is not sufficient.

## Safety and authority analysis

```text
new_authority_created = false
production_reachability_changed = false
signing_or_settlement_authority_changed = false
serialization_boundary_changed = false
```

Any `true` value requires the applicable safety/protocol/economic owner and
independent reviewer.

## Required evidence

```text
positive_vectors =
negative_mutants =
fault_matrix =
exact_commands =
independent_replay =
```

## Downstream invalidation

List packages, schemas, vectors, parsers, clients, light clients, benchmarks,
migration and release evidence that consumed the old interface.

## Implementation ownership

Only `owner_agent` implements the owned interface. The requester waits for an
accepted version/digest and then updates only its own adapter/consumer.

## Review decision

```text
owner_decision =
independent_reviewer =
accepted_interface_version =
accepted_interface_digest =
source_commit =
source_tree =
notes =
```

An accepted request does not itself prove implementation or promote a Gate.
