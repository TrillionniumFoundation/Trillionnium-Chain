# G2C verification and challenge package v1

Status: **MODULE_CLOSED_CANDIDATE for deterministic-reexecution assurance / canonical profile and Node authority blocked**

Package ID: `G2C_VERIFY_CHALLENGE_V1`
Agent: `A14`
Upstream execution candidate: `38993b0893f9fe3fa7ba6995d45f7dff5c870ee7`.

## First objective profile

The only profile exercised by this package is `deterministic-reexecution-v1`. It binds task, lease, attempt, runtime digest, input commitment, output commitment, seed, trace root, profile ID/version/hash and accepted Order coordinates.

## Closed candidate surface

- exact deterministic output reconstruction;
- profile registry lookup with no fallback;
- profile activation, expiry and revocation checks;
- result transition `ResultPending -> ChallengeWindow -> ResultFinal|ResultRejected`;
- one bonded challenge with evidence, provider response and adjudication;
- timeout finalization only after the exact challenge deadline;
- strict distinction between objective, stake-attested and subjective profiles;
- disabled-profile and cross-profile negative corpus.

## Invariants

1. A valid hash or signature is not proof under the wrong profile.
2. Missing runtime/input/output/trace evidence fails before verification.
3. Backend unavailability is not mapped to invalid proof or success.
4. Unknown, disabled, expired or revoked profiles never fall back.
5. One result has at most one live challenge in this launch slice.
6. Challenge success/rejection is a forward transition and never changes Order block identity.
7. Subjective evidence can never produce objective finality, settlement or PoCO weight.
8. This gate emits a result decision only; it moves no economic value.

## Command

```bash
bash scripts/ci/check_deterministic_reexecution_model_v1.sh
```

## Remaining gaps

- frozen runtime/image/compiler/kernel/numeric profile and real executor;
- artifact DA and task/lease proof joins;
- canonical CEV1 profile/receipt/challenge schemas;
- concurrent challenge/appeal/withdrawal and durable outboxes;
- proof-specific ZK/TEE/reproducible-ML assurance and revocation;
- Node/Order authority, crash recovery and settlement handoff.

## Non-claims

```text
g2c_exit=false
verification_profile_enabled=false
result_authority=false
settlement_authority=false
node_integration=false
production_candidate=false
```
