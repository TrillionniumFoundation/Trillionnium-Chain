# TRNM CometBFT Receipt V2 Trust-Anchor Runbook

Status: internal cross-repository contract for the typed Research ingress and
Receipt V2 development tranche. It does not establish production trust or
release readiness.

## Trust Boundary

`CometBftTrustAnchorV1` is an owned, strict-canonical JSON document. It is the
portable boundary consumed by `trnm-finality-verifier`; consumers such as Hepta
do not need to persist borrowed Tendermint or CometBFT implementation types.
The anchor records, and the verifier rebinds, all of the following:

- the exact trusted chain ID, header height, header hash, header time, and
  canonical header protobuf;
- the exact next-validator-set protobuf and its hash in the trusted header;
- the reduced trust-threshold fraction; and
- the trusting period and maximum clock drift.

The anchor is not self-authenticating. Its domain-separated `anchor_hash_hex`
detects byte or field drift after acquisition; it is not a signature and does
not establish who authorized the root. An operator must authenticate the
canonical anchor bytes and expected anchor hash through a pinned genesis or
checkpoint ceremony, an already verified light store, or another explicitly
reviewed distribution channel. Never accept an anchor supplied alongside the
receipt it is meant to verify.

Anchor JSON is accepted only in the exact compact representation emitted by
the canonical encoder. Unknown or duplicate fields, whitespace, alternate
field order or number spellings, non-canonical hexadecimal text, a header/time
mismatch, a validator-set/hash mismatch, or an invalid policy fail closed.
Keep and audit the exact canonical bytes; do not parse and re-emit them through
an unrelated JSON implementation before verification.

## Verification Time and Outcomes

Receipt verification takes an explicit caller-supplied verification time. The
caller must obtain that value from its trusted wall-clock boundary and record
it with the verification result. Tests must inject a fixed time; production
code must not silently substitute a fixture timestamp or a receipt-controlled
timestamp.

An unusable trust anchor, a chain/root mismatch, or an anchor outside its
trusting period is `Untrusted`; it must never be converted to `Final` or treated
as a retry-success. Canonical anchor loading or validation errors must likewise
remain fail closed at the consumer boundary. Receipt evidence that is malformed
or cryptographically inconsistent is `StructuralInvalid`; a well-formed update
that has not met the required trust/finality threshold is `NotFinal`. Only the
explicit `Final` outcome authorizes downstream finality-dependent state.

## What Receipt V2 Proves

For a transaction executed at height `H`, a valid
`CometBftAppHashFinalityReceiptV2` binds one continuous proof chain:

1. the exact raw signed Research transaction and its Comet transaction hash are
   included in block `H` under `header_H.data_hash`;
2. the deterministic `ExecTxResult` at the same transaction index is included
   under `header_{H+1}.last_results_hash`;
3. the application state produced by `FinalizeBlock(H)` is committed as
   `header_{H+1}.app_hash`;
4. an ICS23/JMT membership proof under that AppHash authenticates the exact
   applied-command object, including the Research command ID and command
   fingerprint; and
5. the signed header and validator evidence finalize `H+1` against the
   externally authenticated trust anchor and policy.

The frozen synthetic `FinalityReceiptV1` is not reinterpreted as this receipt.
Receipt V2 is a separate CometBFT/AppHash contract.

Receipt V2 intentionally does not carry the validator-set evidence needed for
`H+2`. It can finalize the transaction at `H` through the commitments in
`H+1`, but it cannot promote `H+1` into a reusable trust root. Fetch and verify
the next validator set and the required light-client evidence through the
normal light-store update path before advancing the trusted state. Never infer
trust-root promotion merely because one Receipt V2 returned `Final`.

## Hepta Domain Binding

Before submitting a typed Research transaction, Hepta must durably record its
expected chain ID, command fingerprint, and the queued
`TrnmCommand.idempotency_key`. When a receipt arrives, its `command_id` must
match that `idempotency_key` exactly. It must not be compared with, or rewritten
from, a local database row UUID, paper UUID, project UUID, outbox UUID, or
request UUID.

Hepta must also require exact chain ID and command-fingerprint equality before
accepting a `Final` result. A replay with the same idempotency key is valid only
when it preserves the same fingerprint and verified receipt identity. Any
identifier or fingerprint mismatch is a quarantined verification failure, not
a new local command. `StructuralInvalid`, `Untrusted`, and `NotFinal` leave the
command pending or failed according to policy and must not unlock ranking,
rewards, or economic claims.

## Anchor Operation and Rotation

1. Acquire the canonical anchor bytes and expected hash through the approved
   external authentication channel.
2. Record provenance, chain ID, trusted height, header hash, anchor hash,
   acquisition time, and approving operator or ceremony.
3. Load and validate the complete anchor before accepting receipts. Do not
   override a failed field or validator-set binding.
4. Supply an explicit trusted verification time for every verification call
   and retain it in the audit record.
5. Match the verified Receipt V2 domain fields to the queued Hepta command.
6. Advance finality-dependent product state only on `Final`.
7. Update or rotate the anchor only through a separately authenticated
   light-store/checkpoint transition. A receipt is not an anchor-update
   message.

At minimum, the audit record should retain the receipt hash, anchor hash,
verification time, outcome, chain ID, command ID, command fingerprint,
transaction index, execution and commitment heights, commitment header hash,
and AppHash. Private signing material is never part of this record.

## Fixtures and Evidence Boundary

Stable canonical receipt, trust-anchor, expected-outcome/hash, and tamper
fixtures live under
`trillionnium/crates/trnm-finality-verifier/fixtures/`. Focused tests and the
deterministic exporter use them to detect cross-repository wire or semantic
drift, including Hepta vendor compatibility. Positive fixtures must reproduce
the exact expected verified fields and hashes; tamper fixtures must remain
non-`Final`.

These files are cross-repository contract and diagnostic fixtures only. A local
single-validator run, a checked-in golden hash, or a focused test pass is not an
externally authenticated checkpoint, multi-validator production evidence,
soak evidence, or release proof. Release evidence must separately bind a clean
immutable revision, authenticated validator topology and trust root, retained
runtime artifacts, and the applicable release gates.
