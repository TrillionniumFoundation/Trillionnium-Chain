# Native PQ quota v3 research boundary

This is a fresh, valueless `pon-native-pq-quota-v3` successor under the
[sole development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
The [NPQ2 account profile](NATIVE_PQ_ACCOUNTS_V2_RESEARCH.md) is unchanged at its
public entry points. A new profile is necessary because the original quota-use
command contains an independent consumer authorization in addition to the
provider's main signature. Replacing only that main signature would leave the
consumer authorization classical.

## Actual implementation and current evidence

The [M00 codec](../../../../trillionnium/crates/trnm-protocol/src/pq_native_accounts_v2.rs)
requires an explicit `AccountProfile`; the original public NPQ2 helpers and decoder
always select `AccountsV2`. NPQ3 selects a distinct NPQ3 version byte, PQP3 packet
prefix, signing-core domain, TPQ1 owner-context domain, transaction-ID domain,
network, parameters and genesis. No input-controlled negotiation or classical
fallback selects this profile. Its SQL schema commitment and statement/removal
tables have separate v3 namespaces. The old opener rejects new settings and
stores, and the new opener rejects the old ones.

The [shared M06 owner](../../../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs)
still owns quota creation, reservation, deadline, per-unit price, fee subtraction,
provider credit and escrow settlement. The legacy path continues to verify its
original inner Ed25519 proof before that settlement. NPQ3 reaches the same private
arithmetic after real ML-DSA checks; it never fabricates an Ed25519 envelope or
skips the old monetary conservation/root requirements.

The [opaque Node wrapper](../../../../trillionnium/crates/trnm-pon-node/src/store/pq_quota_v3.rs)
uses the original typed M05, M06, complete W1, authenticated SQLite, activation,
reorganization and cold-open owners. It exposes no legacy Node escape or network
listener. New [native cases](../../../../trillionnium/crates/trnm-pon-node/tests/native_pq_v3.rs)
and [M06 cases](../../../../trillionnium/crates/trnm-mvcc-fee/tests/pq3_quota_authority.rs)
are required by the [dedicated runner](../../../../scripts/ci/run_native_pq_quota_v3.py).
Their actual terminal observations, including any failure, determine acceptance.
Implementation and parser controls alone do not constitute a native pass.

## Quota authority and replay semantics

Tag 10 reserves a quota with one current-account ML-DSA proof. The original quota
ID binds network, parameters, payer account, payer nonce, consumer, provider,
units and deadline. Its complete NPQ3 frame is **3,821 bytes**.

Tag 11 carries a 72-byte quota/units/result payload and **two actual ML-DSA-65
proofs**. The first resolves the provider's current key and generation from the
selected parent State. The second first reads that parent's actual quota, obtains
its stable consumer account, and resolves that account's current key/generation.
A witness key ID is never an authorization source. Both proof descriptors and
the whole command are signed together; each role has its exact owner context.
The complete frame is **7,314 bytes**, including both signatures.

The provider's ordinary chain nonce advances once. As in the original inner
consumer consent, the consumer signs the exact provider command and operation
sequence; this does not consume a second, independent consumer transaction nonce.
Changing provider, quota, units, result, expiry, fee ceiling or either witness
changes the signed statement. A provider replay is refused by ordinary M06 nonce
checking. A signature from another current account cannot replace the quota's
actual consumer proof. A signature from a retired consumer key cannot authorize a
new branch state that has advanced that consumer's generation.

Either participant's authority-changing command is exclusive with a quota use in
the same block, in both orders. The check includes the consumer as an authority
read even though the provider is the transaction sender. Quota-use key resolution
uses the immutable block parent; a quota first reserved in that same block is not
an existing parent quota and does not acquire consumer authority from an earlier
scratch transaction. A valid chain reorganization can restore the original
consumer generation and provider nonce; the original pool reauthorization then
rechecks them. This is chain state semantics, not an off-chain revocation reset.

At the unchanged 524,288-byte transaction budget, 71 complete uses occupy 519,294
bytes and 72 occupy 526,608 bytes. The component control requires 142 actual
signature verifications for the 71-command accepted cohort, preserved consumer
nonce, provider nonce 71, exact remaining units, and no input-State mutation on
rejection. The native capacity case also requires five actual bounded pool bundles, exact
packet and SQL byte readback, provider nonce 71 and unchanged consumer nonce.
These capacity boundaries are not throughput measurements.

## Required native and regression cases

The new Node target must run its full five-case inventory without ignored or
filtered substitution: actual pool/complete W1/SQL quota use with detach cut and
cold recovery; actual consumer rotation with old-proof rejection and heavier-fork
reauthorization; exact old/new settings, packet and store refusal; and an actual source-Node
checkpoint imported into this same NPQ3 profile, claimed by two real PQ proofs,
then used as the stable quota consumer through cold open and a heavier fork; and
71 full dual-proof commands admitted through the actual M05 pool, full W1 packet,
SQL activation and cold reopen, with a 72nd command rejected without spending.
Successful calls emit twenty-one bounded phase observations, including full production W1
reference verification; those are shared-host call times, not isolated CPU or
worst-case budgets.

The dedicated lane also runs the entire original M00 and M06 unit targets, the
eight new M06 quota cases, the existing two PQ2 capacity cases, all nine existing
PQ2 native cases, and all six existing PQ1 native cases. It retains exact source
checks, compiler identity, raw command outcomes, the native binary hash, formatting
and strict Clippy for M00/M06/Node all targets and features. Compiled-only output,
missing cases, ignored/filtered substitutions and unrelated old cases do not pass
its exact readers.

## Source-native continuation on 2026-10-28

The [retained continuation](../../../../evidence/pon-pq-quota-closure-20261028/README.md)
first reproduced a real `PQ2_ENCODING` failure when the migration apply owner
reparsed a valid NPQ3 claim as NPQ2. That private apply now selects the existing
strict decoder from its pinned configuration, preserving both public profiles.
The native quota suite then actually executes all five cases, including the
same-profile source checkpoint claim and the complete 71-command pool/packet/SQL
capacity path. The additional M06 controls cover rotated providers, registered
consumers and parent-only quota authority; both old native profiles are retained.

Current changed production libraries were rebuilt with real Rust 1.95.0 against
recorded immutable external link artifacts. The exact command/source/binary
records distinguish actual native execution from full Cargo qualification.
The locked offline Cargo graph resolves 173 packages with 26 workspace members;
metadata is not a build. This continuation also preserves the initial failed
native case, the cancelled fresh Cargo attempt and strict Clippy failures.
The exact final counts and terminal scopes are in its summary; the dedicated
all-targets/all-features Cargo lane remains a separate acceptance gate.

## Boundaries that remain open

NPQ3 supports existing NPQ2 tags 1–5 and account commands plus quota tags 10–11.
It does not migrate contribution/evaluation/release/reward or work-registration
owners (tags 6–9 and 12–24), remaining inner signatures, transport, service,
governance, custody, History authorization or Hepta Final-use. The explicit NPQ3 trusted-migration constructor reuses the existing pinned
projection and claim rules under its fresh network/signature/SQL context; the
NPQ2 constructor remains separate. Both still require independent prior-PQ trust
and source checkpoint selection. Neither proves source-chain retirement or
independent registry history. Import of positive pre-existing quota/release
liabilities remains refused by the original projection; the new native case
creates its quota after the imported consumer has actually claimed. No old store or live network is upgraded in place.
Quantum W1/proof security, physical I/O and source-preserving operational migration
remain separate gates. Whole-chain PQ acceptance, P1 completion and production
activation remain false.
