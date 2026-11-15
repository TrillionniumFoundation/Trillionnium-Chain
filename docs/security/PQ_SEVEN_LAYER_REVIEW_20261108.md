# Seven-layer PQ composition review — 2026-11-08

Status: **HOLD / NO-GO**. This continuation strengthens source consistency,
records actual effect boundaries, and models root/recovery policy refusals.
It does not change Rust authorization, native execution, signed wire formats,
consensus rules, deployed roots, or production permissions. A successful source
check or hypothetical policy check cannot authorize an effect.

## 1. Fixed candidate and retained failures

The selected local base is [PR #790](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/790)
at `88568e2511fcf166e6824947ac97b06b72104385`. It extends the lifetime-accounting
candidate; this work has not merged the independent #796 authority candidate.
The [remote observation](../../evidence/pq-seven-layer-composition-20261108/remote-candidate-observation.json)
records main as `dd6e1c3cbeacbdc532b0679297835b3a0aac78f0` and #796 as
`01e2c4c010c3cf65d1cf094368961efc1abab445`. The observation is not atomic and is
not evidence that any of those candidate heads were deployed or merged.

The retained [#796 command summary](../../evidence/pq-seven-layer-composition-20261108/upstream-796-inventory-summary.json)
and [inventory readback](../../evidence/pq-seven-layer-composition-20261108/upstream-796-inventory-readback.json)
refer to tested commit `ca3c4f88afc70399000b18fc7d68cfa62e57fb2f`:
**31 of 32 command gates passed; the aggregate result is FAIL**. The
`node-release-owner` command exited 101, with 38 passed, 2 failed, and 1 ignored.
The two failed tests are
`release_owner::service_tests::clock_reply_then_real_elapsed_expiry_refuses_without_cas`
and `release_owner::service_tests::durable_preparation_then_real_elapsed_expiry_refuses_without_cas`.
The ignored native consumer was not executed. These observations remain failed;
they are not local results for this continuation or a pass for a later head.

The [#796 dual-family experiment record](../../evidence/pq-seven-layer-composition-20261108/upstream-796-root-quorum-result.json)
contains real component-signature work but reports no root effect, activation,
production qualification, or independent host attestation. The new policy
model below does not import that experiment as runtime authorization.

## 2. What this continuation adds

The [lifetime source lock](../../config/pon/pq128-source-lock-v1.json) binds the
declared experiment revision to exactly 15 event-owner paths. Generation checked
regular Git blobs at `12e510b211110d93d9ead07e02c07a1eecc28ae9`, read their actual
`git show` bytes, and matched all 15 against the working files before hashing.
The runtime checker compares those reviewed digests with descriptor-bound reads;
it works without Git history in shallow CI. The
[contract and generation procedure](PQ128_LIFETIME_BUDGET_V1.md) explain that
this is declared-path consistency, not authenticated provenance, a complete
dependency closure, a deployed-byte check, or an immutable multi-file snapshot.

The [root/recovery policy model](PQ_ROOT_RECOVERY_POLICY_V1.md) checks every
declared normal, rotate, revoke, recover, and policy-change route. Each requires
two distinct ML-DSA-87 approval claims and two distinct SLH-DSA-SHA2-256s claims
over one complete statement. It checks current and successor policies, supplied
context, retained nonce history, and explicit unknown observations. It verifies
no signatures and grants no authority, including when every observation is
declared `scenario-assumed`.

The [authority/effect register](PQ_AUTHORITY_EFFECT_REGISTER_V1.md) records seven
reviewed source routes and their bounded effect scopes. Its 44 exact source files
are checked against the fixed candidate. Source consistency is not a complete
call graph, dynamic reachability proof, migration, or whole-chain qualification.

## 3. Seven layers: evidence and remaining obligations

| Layer | Current evidence and source boundary | Still required |
| --- | --- | --- |
| Accounts, transactions, service settlement | The [effect register](PQ_AUTHORITY_EFFECT_REGISTER_V1.md) distinguishes native PNX1 account effects from the compatibility transfer validator, portable settlement kernel, and research-state handler. | Close every accepted classical route at its actual owner and irreversible effect; validate migration, task/payment authorization, and external settlement together. |
| Publication and root authorization | The [root/recovery model](PQ_ROOT_RECOVERY_POLICY_V1.md) rejects weaker routes in the full current or proposed policy. The separate #796 signature experiment retains its own evidence. | Verify actual current authority, new-key possession, independent custody, revocation, recovery, and actual loaded/executed bytes in the installed owner. |
| Content commitments | Existing manifest/dependency owners are identified in the [lifetime register](../../config/pon/pq128-lifetime-budget-v1.json); the remote snapshot separately identifies [#789](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/789). | Commit to complete original bytes, chunk structure, dependencies, and relevant execution context; hashing a legacy digest again does not remove its old binding limit. #789 is not integrated evidence here. |
| STARK / FRI | The [lifetime obligations](PQ128_LIFETIME_BUDGET_V1.md) retain proof/refinement and shared-primitive gaps. The snapshot separately identifies [#792](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/792) and [#795](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/795). | Map actual field, extension, FRI parameters, relations, permitted recursion, Merkle encoding, transcript, extractor, and query costs to applicable QROM theorems. No other branch's proof or bound is inherited. |
| PoN work and consensus | The native work and ledger owners remain separate events in the lifetime register; [#794](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/794) is an independently observed joint-consensus candidate. | Establish one model covering legal quantum work strategies, difficulty, timestamps, branch selection, accumulated weight, and lifetime adversary resources. Local scenario results do not prove the cheapest legal strategy bound. |
| Recovery | The [policy model](PQ_ROOT_RECOVERY_POLICY_V1.md) exposes matching-anchor, currentness, durable-history, and external-effect obligations; the effect register identifies actual owner boundaries. | Obtain independently retained anti-rollback anchors, protect complete revocation/operation history from reorganization and snapshot rollback, and reconcile actual external effects before resuming use. |
| Lifecycle | The [checker](../../scripts/ci/pq_lifetime_budget.py) validates exact rational accounting and the reviewed source lock. Eight event terms and four shared-public-primitive query budgets remain unknown. | Prove full event coverage and applicable reductions for the specified lifetime, users, messages, failures, offline search, preprocessing, shared primitives, and legal initial advice; retain null for the complete actual bound until then. |

## 4. Actual effects must remain distinct

The native account-transfer trace starts with `pon_wire::Envelope`, proceeds
through `pon_executor::prepare` to `apply_authenticated_application`, performs
account debit/credit, and reaches Node persistence/activation. The compatibility
`trnm-types::TransferTx` path has validation behavior; this source review found
no Node caller establishing that it owns the native account effect. The exact
files, anchors, and limits are in the [route matrix](PQ_AUTHORITY_EFFECT_REGISTER_V1.md).

The classical portable settlement kernel and classical research-command state
handler have their own effects; they cannot be declared migrated merely because
a PQ envelope exists elsewhere. Hepta V1 compares supplied owner context, while
V2 is a separate path and is not proof of FinalUse. Discovery V1 reaches a
provider directory and SQLite/content cache, not payment or execution permission.
Reference release-finality observation uses two certificate readers and produces
facts without a state-changing owner; the separate formal simulator is profile
context. These distinctions prevent a verifier result from being
reported as a completed transaction, installation, settlement, or authorization.

## 5. Standards and probability interpretation

[FIPS 204, Section 4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
places ML-DSA-65 in category 3 and ML-DSA-87 in category 5. These are algorithm
resource-comparison categories, not whole-chain quantum security bit counts.
Section 5.4 also conditions retention of the parameter set's strength under
application-level prehashing on a suitable approved hash/XOF. Its digest-length
requirement is at least twice the stated classical collision-strength parameter;
length alone is insufficient, and expanding an old digest does not bind new
original bytes. Pure signing and HashML-DSA are distinct interfaces.

[FIPS 205, Section 11](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf)
states its parameter-set targets for up to `2^64` signatures per key and explains
that EUF-CMA classification does not automatically include message-bound
signatures. It does not certify this project's custody or recovery protocol.

[NIST's PQC FAQ](https://csrc.nist.gov/projects/post-quantum-cryptography/faqs)
describes dual signatures on a common message with all components verified.
Under a justified common experiment and the required binding reductions, an AND
forgery event is contained in each component break event, allowing a bound by
the smaller applicable component bound. Multiplying component probabilities
requires additional assumptions. An OR recovery path introduces an additional
acceptable attack route and cannot inherit the AND-only condition; see
[RFC 9955, Section 6.2](https://www.rfc-editor.org/rfc/rfc9955.html#section-6.2).

Union accounting does not require independent events, but every included bound
must apply to the same experiment and scope. A missing theorem or unknown query
budget is not zero. The [QROM reduction literature](https://eprint.iacr.org/2025/2166)
has restoration and extraction hypotheses; citing it does not establish the
implementation mapping. Complete dependency, shared-oracle, and runtime-owner
composition remain obligations even when partial arithmetic is numeric.

## 6. Validation and continuation boundary

The source-lock changes were checked with 58 lifetime-budget tests and 49
claim-guard tests, all passing. New refusal controls were run against the prior
checker first and failed as expected; retained red observations are not erased.
The research CLI remains HOLD with `source_revision_bound: true` limited to
`declared-event-paths-only`. The arithmetic example remains HOLD and `unbound`.
Both retain `actual_lifetime_failure_bound: null` and false qualification flags.

Root-policy and authority/effect controls retain their own bounded scope and
command receipts. Exact-source integration, links, corpus pins, and CI-contract
checks must be evaluated on the final composition. None of these Python model
or source checks is a new native Node campaign or a repair of #796's failures.
The next qualification step must connect the actual owners and independent
evidence across the seven layers; whole-chain PQ, production activation, and
complete lifetime security remain unqualified.
