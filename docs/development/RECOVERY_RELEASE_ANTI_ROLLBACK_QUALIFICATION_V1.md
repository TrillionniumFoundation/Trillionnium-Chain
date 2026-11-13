# Cross-domain anti-rollback and loaded-byte release qualification (proposal v1)

Status: **normative candidate / NOT IMPLEMENTED / NO-GO for production**. This contract augments [M08](../modules/M08_FINALITY_RECOVERY_TECHNICAL_SPEC_V1.md), [M15](../modules/M15_NODE_RELEASE_TECHNICAL_SPEC_V1.md) and [PoN recovery migration](../protocol/pon-nakamoto-v1/RECOVERY_MIGRATION.md). It does not assert that the current native node or Hepta ordinary host implements these rules.

## 1. Threat and separation of authority

An attacker can restore all files of domain A to a three-day-old backup, including CURRENT, WAL, SQLite, key epochs, local witness, cached signatures, unspent grants and unacknowledged provider calls; cannot forge signatures or compromise independent domain B. A's wall clock and copied secure-storage files are not trustworthy freshness sources. A recovered historical signature proves only historical validity, never **current effect authorization**.

* **Reorganizable chain state:** balances, branch-derived entitlements, canonical inclusion, pending confirmations and release pointers follow validated preferred-chain consensus and reorg rules.
* **Monotone effect state:** consumed-capability IDs, operation IDs, external provider outcomes, revocation and minimum-key-epoch frontiers, witnessed checkpoint/generation and installed/current-use eligibility are never inferred only from a restored chain snapshot.
* **Unknown operations:** an attempt with missing ACK is not presumed failed. Keep the same operation identity and query the authoritative provider or independent effect owner. No new nonce, fresh lease or replacement operation until reconciliation concludes safely.
* **Current-use authority:** install, adopt, execute and pay require fresh validation against independently preserved policy state at the actual effect boundary. Prior chain confirmation, digest, signature or successful download is insufficient.

**Impossibility boundary:** if every authority, provider journal and witness independently entrusted with the future can all roll back to the same past, no signature algorithm can distinguish that past from the original present. For this failure mode, refuse effects until an uncompromised authority or externally durable record is consulted. Do not silently fail open.

## 2. Independently operated recovery floor

B must hold an authenticated, durable, monotone checkpoint outside A's backup/failure/administrative domain. Suggested checkpoint fields: `chain_id`, `authority_id`, `log_id`, `sequence`, `root`, `revocation_floor`, `min_key_epoch`, `effect_journal_frontier`, `release_generation_floor`, `protocol_profile`, `signature_and_quorum`. Canonical serialization and domain-separated hashing are mandatory. This is an application protocol: a generic transparency-log witness CAS alone does **not** authenticate business effects, key rotation or release entitlement.

A boot sequence MUST: enter quarantine; disable network effect admission, payments, task dispatch and model FinalUse; recover local storage; contact B and verify its signature/quorum, trust root, chain/log identity, sequence and root; reject a decreasing or conflicting checkpoint; reconcile all unknown external effects; rebuild current-use eligibility from the current chain plus B's irrevocable floors; then publish a new generation and unlock explicit owners. If B is unreachable, fail closed for effects (read-only observability permitted with a stale-state label). A database transaction is not proof of power-fail durability: test fsync/rename/dir-fsync and independently retained remote state on the target filesystem.

**CAS lost-ACK rule:** B stores the expected-old comparison and committed new root durably *before* replying. When A's ACK is lost, A queries B with the **same** log/operation ID and expected-old/root. If B reports the committed result, resume without repeating any provider effect; if it reports mismatch, quarantine and reconcile. An idempotency key is necessary but not sufficient when the provider's retention horizon expires; a durable independent effect receipt or unresolved quarantine must bridge that gap.

## 3. Effect identity and state machine

Identity: `H(domain || chain_id || owner || task_id || lease_id || attempt_id || provider || effect_kind || target || payload_digest || authorization_generation)`, encoded canonically. The persisted signed intent and provider idempotency key bind this identity; neither may be replaced merely because a chain reorg or local recovery removed a nonce.

Allowed states: `PREPARED -> IN_FLIGHT -> UNKNOWN | SUCCEEDED | REJECTED`; `UNKNOWN -> SUCCEEDED | REJECTED` only on authoritative reconciliation; `SUCCEEDED` and consumed/revoked authority are terminal from the original operation's perspective. Compensation is a **separate** explicitly authorized operation linked to the original receipt. Never assume transport failure implies provider non-execution. Record the intent durably before dispatch and the authoritative receipt after completion; report the acknowledged status only after that record is durable.

On a chain reorg, retain the effect receipt and mark its authorization orphaned; suspend any further effects and separately settle the economic obligation. Chain reorg never rewinds remote money movement or revives a consumed grant.

## 4. Loaded-byte software and Cell release closure

A signed Git commit is source provenance, not sufficient authorization to load. A versioned release manifest MUST bind cryptographic digests with byte lengths, media types and resolver rules for executable ELF, interpreter, dynamic libraries, loader paths, plugins, config, environment allowlist, guest program, verifier code/parameters, model Cell weights/shards, tokenizer, router, schema, dependency closure, build provenance and policy/profile. Resolve by immutable digest and reject mutable tags, unpinned remote imports, missing dependencies, path/symlink escapes or unexpected dynamic loads. For platform-dependent closures, measure and attest the exact platform-specific closure.

Distinct audited transitions: `CANDIDATE -> VERIFIED_DOWNLOAD -> VERIFIED_INSTALL -> ADMITTED_RELEASE -> ACTIVATED_GENERATION -> FINAL_USE_RECEIPT`. Each has its own owner, evidence, signature and policy check; only the owning runtime can attest actual loaded hashes and FinalUse. Learning/evaluation scores can support eligibility, but never mint install, provider-call or final-use capabilities. Current key epoch and revocation floors must be refreshed immediately before sensitive adoption/use; expired or offline proofs do not grant fresh privileges.

Bind manifest/version, evaluator protocol, owner signatures, current chain authorization and monotone release generation. Record the actual mapped binaries/libraries and weight/tokenizer/router content identity **after loading**, or fail closed. TOCTOU-resistant handles/content-addressed stores and isolated loader namespaces are required; a pre-load filesystem hash alone does not prove what executed. Preserve old-version historical inference receipts, but prevent new FinalUse after revocation, freeze or rollback unless separately authorized.

TUF-style roles, thresholds, expiry and delegations are useful update-metadata references, including a planned PQ profile, but an adapter or signature check does not establish a complete TUF client or operational anti-rollback. Define root rotation, consistent snapshot, freeze/rollback detection and trusted-time source independently.

## 5. Mandatory dual-domain adversarial acceptance matrix

Use physically/administratively independent A and B; record separate process, storage, key, backup, credential and fault domains. Do not count two directories on one host as independent.

| Test ID | Fault injection | Required observable result |
| --- | --- | --- |
| RR-01 | Restore A's full filesystem three days backwards; B retains newer signed checkpoint | A remains quarantined, detects stale sequence/root and cannot execute old grants |
| RR-02 | Restore A's old key epoch and locally unrevoked authorization | B's epoch/revocation floors reject signing, dispatch, payment and FinalUse |
| RR-03 | B commits CAS; discard A's ACK; restore A | A queries same op/expected-old; no new nonce, no duplicate external call |
| RR-04 | Provider succeeds; drop ACK; crash before local receipt | Recovered operation stays UNKNOWN; authoritative query reconciles exactly one effect |
| RR-05 | Provider is unavailable or idempotency retention expired | No automatic retry with new identity; remains UNKNOWN/quarantined |
| RR-06 | Reorg removes task/nonce/lease after actual provider effect | Receipt survives; new effect blocked; orphaned liability reconciled |
| RR-07 | Restore old CURRENT and signed release; B keeps newer generation/revocation | Old installed bytes cannot acquire current-use capability |
| RR-08 | Swap dynamic library, interpreter, tokenizer, router or model shard after manifest verification | Actual closure mismatch blocks activation/FinalUse, no old receipt rewritten |
| RR-09 | B unavailable, equivocation detected, or B's signature/root invalid | Effect owners fail closed, surface measurable reason codes |
| RR-10 | Simultaneously restore A and B with no independent surviving record | No false recovery-security claim; demonstrate documented impossibility/fail-closed policy |
| RR-11 | Power cut across intent, CAS, publication, provider ACK and FinalUse boundaries | No double effect, no silent lost intent; replay uses same IDs and authoritative receipts |
| RR-12 | Competing CURRENT changes with concurrent owner adoption | Compare-and-swap generation fencing ensures at most one admitted current generation |

For every run preserve: exact source commit, binary/config/weight digests, signer key IDs and epochs, B checkpoint/provenance, clock assumptions, A/B storage failure independence, injection cut, process tree, provider receipt, expected vs actual effects, all failed/cancelled trials, resource limits, raw logs and verifier identity. Pass only on independently observed external effects and native ordinary-host FinalUse; unit and local process-crash tests are preliminary evidence.

## 6. Gate and rollout

**Block production** until: (G1) independently deployed B and secure fail-closed recovery; (G2) authoritative effect reconciliation with stable identity and retention policy; (G3) rollback-safe PQ key/authorization lifecycle; (G4) actual loaded-byte closure and owner-specific FinalUse receipts; (G5) all RR tests with real power/process/network faults and independent evaluator; (G6) signed release metadata/root rotation and source-to-runtime provenance. Maintain a separate status per gate. This does not resolve PoN work-hardness, STARK soundness, native consensus admission, throughput or ordinary Hepta qualification.

References (design context, not evidence of implementation): [C2SP transparency log witness v1.1](https://c2sp.org/tlog-witness@v1.1.0), [TUF TAP 21](https://github.com/theupdateframework/taps/blob/master/tap21.md).
