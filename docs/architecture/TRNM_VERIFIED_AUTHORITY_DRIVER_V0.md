# Verified Authority Driver v0

Status: wiring-only candidate orchestration; no domain, network, signing, finality or production activation authority.

Related contracts:

- [Production Authority Session v0](TRNM_PRODUCTION_AUTHORITY_SESSION_V0.md)
- [Authenticated Authority Input Ports v0](TRNM_AUTHENTICATED_STAGE_FACT_PORT_V0.md)
- [Candidate Authenticated P2P Admission v0](TRNM_CANDIDATE_AUTHENTICATED_P2P_V0.md)
- [Candidate Pacemaker I/O v0](TRNM_CANDIDATE_PACEMAKER_IO_V0.md)

## Purpose

`ProductionAuthoritySessionV0` enforces authenticated ingress, complete-receipt recovery and verified stage facts. `ProductionAuthorityDriverV0` removes one remaining orchestration ambiguity: callers cannot select an arbitrary target stage through the driver.

The public sequence is named explicitly:

```text
recover
-> admit_ingress
-> seal_application
-> persist_safety
-> persist_sign_intent
-> confirm_signature
-> apply_finality
-> confirm_checkpoint
-> publish_outbound
```

Each method requires the corresponding `AuthorityIngressSourceV0` or `AuthorityFactSourceV0`. A method rejects a claim for a different named stage before invoking source authority. The underlying session still checks operation identity, predecessor stage, predecessor record digest, source identity/sequence, exact replay and authenticated post-write readback.

## Authority boundary

The driver owns no source implementation and cannot create a fact claim on behalf of a domain owner. It does not contain application execution, Safety rules, canonical sign bytes, a private key, signature verification, finality proof, checkpoint CAS, outbox, P2P or timer logic.

The generic source type in each call preserves error provenance. Source rejection and wrong named-stage admission occur before durable mutation. Session write uncertainty still moves the session to `Recovering` until complete authenticated recovery succeeds.

## Required real composition

A live candidate must bind each named method to an independently reviewed source adapter and prove that no alternate path can invoke the durable coordinator with caller-selected digests. It must also connect authenticated P2P and pacemaker effects to the same operation identity and durable response-loss protocol.

## Acceptance and non-claims

Required acceptance includes fixed-toolchain tests and strict Clippy, exact-head and prospective-merge replay, wrong-method/source-substitution/token-reuse mutants, dependency-closure review and independent M03/M06/M07/M08/M15/security approval.

Reference coordinators and test sources prove only the wiring state machine. They are not live validator, network, HSM, finality, physical power-loss, multi-host, audit, soak or governance evidence.
