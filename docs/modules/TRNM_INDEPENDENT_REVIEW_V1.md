# Module ownership and independent acceptance contract v1

Status: **candidate review policy; no people appointed and no independent acceptance claimed**. Primary module: M17; consumers: every module and M15 release composition.

This contract complements the sole Plan V2 and `TRNM_DOCUMENTATION_AUTHORITY_V1.md`. It does not replace protected-branch review rules, provision teams, change membership, dismiss reviews or authorize administrator bypass.

## 1. Distinct roles

| Role | Responsibility | Cannot establish |
|---|---|---|
| Implementation owner | Maintain source, explain invariants, propose fixes, supply reproducible evidence | Independent acceptance of their own work |
| Consumer reviewer | Verify the versioned producer contract and real consuming paths, including failure and upgrade behavior | Expertise outside the reviewed domain merely by being a CODEOWNER |
| Independent specialist | Review a named risk domain, reproduce adversarial cases, sign findings against exact inputs | Release authority, activation, or unlimited certification of other domains |
| Release/custody authority | Verify aggregate evidence, key/operational custody and authorized promotion | Missing specialist findings, missing execution, or an author's self-approval |

The repository fallback owners in `config/module-coverage-v1.toml` are routing/maintenance contacts only. They are not automatically specialist reviewers. Two usernames are not proof of independence. No new named specialist is inferred from repository permissions or contribution counts.

## 2. Required expertise and deliverables

| Domain ID | Demonstrable competence | Required acceptance deliverable |
|---|---|---|
| `consensus` | Weighted BFT safety/liveness, locks, QC/TC, epoch handoff and state-machine modelling | Rule-to-code review; partition, conflicting-QC, timeout, empty-block and epoch counterexamples; explicit assumptions and unresolved cases |
| `cryptography` | Canonical encodings, strict Ed25519/key admission, domain separation, proof composition and HSM protocols | Independent byte/signature vectors, malformed-key/signature cases, context substitution, proof-class isolation and custody interface findings |
| `storage-recovery` | Database/filesystem durability, WAL/fsync, crash consistency, fencing, external monotonic anchors | Complete write/publication crash matrix; source-or-target recovery; coherent rollback and device/power-loss evidence boundaries |
| `economics` | Adversarial incentives, Sybil/related-party models, conservation, bonds and challenge/griefing costs | Parameter assumptions, collusion and subsidized-demand analysis, multi-asset invariants, sensitivity results and activation restrictions |
| `execution` | Deterministic state machines, concurrency/MVCC, resource metering and authenticated state | Independent serial oracle, conflict/re-execution and 1/2/4/8-worker root/fee/event equivalence |
| `network-security` | Authenticated protocols, replay, transport resource exhaustion and fault injection | Frame/session/lease traces, bounded allocation/work, slow-peer/flood/partition tests and local-unavailability semantics |
| `application-security` | Delegated authorization, task/escrow/challenge state machines and atomic accounting | Every transition and terminal path, shared-budget/revocation races, replay and unavailable/inconclusive/invalid distinctions |
| `client-proofs` | Light-client trust, proof verification, state sync, versioned APIs and migration | Independent client/parser, stale-anchor and downgrade negatives, verified-state installation and honest UI proof/freshness labels |
| `release-supply-chain` | Reproducible builds, feature/dependency closures, CI evidence and artifact provenance | Exact-head and merge replay, dependency graph, artifact/signature/provenance checks, inherited failure accounting |

One person may cover multiple domains only when qualifications and separate findings establish each competence. All four critical domains—consensus, cryptography, storage-recovery and economics—need explicit specialist coverage where touched; a generic security approval is insufficient.

## 3. Qualification, independence and appointment

The appointment authority collects a stable identity, organization/employer, relevant work or audit references, domain scope, verification-key fingerprint, validity window and signed acceptance of the assignment. Qualification evidence is independently checked, rather than accepted because a registry row says qualified. Sensitive personal details are not placed in this repository; retain appropriate access-controlled references and public fingerprints instead.

Require disclosure of authorship, design participation, reporting relationships, common control, financial interests and compensation. Authors, co-authors and material implementers cannot be independent acceptors of the same change. A second account controlled by the same person does not satisfy distinct-reviewer requirements. Paid review is disclosed and assessed for conflicts; payment alone neither proves nor disproves independence.

A maintenance team can nominate candidates but cannot self-certify them. Appointment approval, identity/key verification and conflict disposition must come from an authorized party distinct from the reviewed author. Missing qualification, expired appointment, undisclosed conflicts, shared identity or revoked key leaves the slot unfilled.

For a cross-module change require producer maintenance review, affected consumer review, and each required specialist domain. Existing repository minimum approvals remain a floor, not a substitute for these roles. Record whether any reviewer occupies multiple roles and why that is permitted; the independent signer must remain outside the authorship set.

## 4. Exact-input review statement

A promotion-capable statement contains the following logical information, serialized and authenticated by the existing external-evidence contract—not by an invented new consensus codec:

```text
statement_id, schema_version, repository
source_commit, source_tree, base_commit, prospective_merge_commit, prospective_merge_tree
plan_digest, documentation_registry_digest, protocol/profile/parameter digests
module_ids, requirement_ids, producer_modules, consumer_modules
reviewer_identity, organization, appointment_id, domain_ids, key_fingerprint
qualification_evidence_refs, conflict_declaration_ref, appointment_validity
commands, toolchain/dependency/feature/configuration digests, raw_artifact_digests
positive_and_negative_vectors, mutant_results, reproduction_scope
findings, severity, assumptions, unresolved_requirements, explicit_non_claims
verdict, signature, immutable_statement_location
```

An empty findings array is not evidence of a completed audit. A reviewer records the tested scope and any excluded boundaries. A link to a review, an unsigned JSON object or a plain `approved` string is not an authenticated statement. Immutable artifact digests and exact-source equality are verified before consuming a verdict.

Requirement-level findings include exact normative clause and code symbol/range, input/pre-state, expected result/error, observed result and reproduction. Sign-off distinguishes design completeness, implementation conformance and deployment qualification. A protocol specialist cannot implicitly attest to physical power loss merely by approving a state-machine model.

## 5. State machine and failure policy

```text
vacant -> nominated -> qualified -> assigned -> review-in-progress
        -> changes-requested -> review-in-progress
        -> signed-findings -> authenticated-acceptance
```

These are review-process states, not chain wire tags. Any change of reviewed inputs moves affected acceptance to stale; expiry or key revocation moves it to invalid; an undisclosed conflict reopens appointment review. Rejected/stale statements remain historical evidence, not active approval. A different PR head, a restacked base or changed consumer invalidates affected acceptance even if filenames are unchanged.

Only the existing authenticated evidence intake plus protected review can recognize acceptance. The documentation checker cannot appoint reviewers or authenticate expertise. It rejects attempts to encode a local accepted status in the navigation registry. The registry deliberately records all independent reviewer assignments as vacant until real appointments and authenticated findings exist; this is an open requirement, not a fabricated completed audit.

## 6. Reviewer checklist and acceptance rule

For each affected requirement the independent reviewer resolves the applicability tuple, implements or checks the independent oracle, reproduces positive and adversarial cases, checks concrete error/side-effect/recovery semantics, traces every real consumer, verifies resource and compatibility bounds, and records counterexamples. The implementation owner fixes the source; the reviewer reruns on the resulting exact head. Independent vectors must not simply call the production implementation to obtain their expected values.

Acceptance requires all required role/domain statements, valid appointments and signatures, matching input digests, no unresolved blocking findings, and all applicable exact-head/merge execution evidence. It does not automatically authorize release or activation. Missing domain coverage, unavailable raw evidence, self-review, stale results, skipped commands, failed tests or unresolved ambiguity must block the affected acceptance.

Examples that must not pass: two fallback CODEOWNERS with no domain qualification; author and alternate account; economic sign-off used for cryptography; signed review of an ancestor; a simulation presented as HSM evidence; valid signatures over the wrong parameter set; a release report synthesized from a directory count.
