# TRNM CometBFT Receipt V2 Trust-Anchor Runbook

Status: internal cross-repository contract for the typed Research V1 and
frozen Paper Raid finality V2 ingresses in consensus App v6, plus the Receipt
V2 development tranche. Paper Raid V3 wire and verification types are
preparation for a future App v7/new-genesis ceremony; App v6 rejects V3
ingress deterministically. This does not establish production trust or release
readiness.

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

1. the exact raw signed typed transaction (Research V1 or App-v6 Paper Raid
   finality V2; a future App-v7 receipt may carry Paper Raid finality V3) and
   its Comet transaction hash are included in block `H` under
   `header_H.data_hash`;
2. the deterministic `ExecTxResult` at the same transaction index is included
   under `header_{H+1}.last_results_hash`;
3. the application state produced by `FinalizeBlock(H)` is committed as
   `header_{H+1}.app_hash`;
4. an ICS23/JMT membership proof under that AppHash authenticates the exact
   domain-specific applied-command object, including the command ID,
   fingerprint, object namespace/version, and canonical value; and
5. the signed header and validator evidence finalize `H+1` against the
   externally authenticated trust anchor and policy.

The frozen synthetic `FinalityReceiptV1` is not reinterpreted as this receipt.
Receipt V2 is a separate CometBFT/AppHash contract.

Receipt verification proves that the Chain accepted and committed the exact
typed Paper Raid tuple under its consensus rules. It does not connect to the
Hepta database or independently rederive the upstream Paper/revision,
evaluation, reproduction, Appeal, consent, or Research Session source graph.
That source-graph derivation and seal remain a Hepta-side responsibility and
must be compared field by field with the verified typed command; AppHash proof
membership is not a substitute for that comparison.

Receipt V2 intentionally does not carry the validator-set evidence needed for
`H+2`. It can finalize the transaction at `H` through the commitments in
`H+1`, but it cannot promote `H+1` into a reusable trust root. Fetch and verify
the next validator set and the required light-client evidence through the
normal light-store update path before advancing the trusted state. Never infer
trust-root promotion merely because one Receipt V2 returned `Final`.

The current App-v6 authenticated-state pruning policy retains a rolling proof
window of 8,192 versions and advances its query floor at 256-height pruning
boundaries; it is not an indefinite historical proof service. CometBFT block,
result, and validator retention is a separate operational boundary and may be
shorter. Collect and archive the object proof, headers, results, validator
evidence, and canonical receipt before either side prunes the execution
evidence. A previously collected self-contained receipt remains independently
verifiable, but a pruned node may no longer be able to assemble a new
historical receipt.

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

For Paper Raid, a `Final` verifier result additionally returns the exact typed
domain command decoded from the AppHash-proven raw transaction. App-v6
submissions and receipts use `SignedPaperRaidFinalityCommandV2`. The verifier
also has an explicitly distinct `SignedPaperRaidFinalityCommandV3` result for
future App-v7 evidence, but this does not activate V3 consensus ingress in App
v6. Hepta must require the expected version and compare that typed command field
by field with its sealed preparation: Paper/submission,
bundle/release/consent, MatchEvidence, final evaluation and reproduction,
appeal status and lineage, policy hashes, timestamps, and all four locked
eligibility flags. It must never reinterpret a V2 command as V3 or vice versa.
A caller-supplied JSON sidecar or digest summary is not a substitute for this
verified typed command.

## Paper Raid offline signing lane

Hepta prepares and seals the scientific-finality tuple but does not retain the
Chain authority private key. After the exact Chain revision is vendored, it
emits the canonical commitment CBOR and deterministic command identity. An
operator-controlled signer then runs:

```text
trnm-research-receipt-v2 paper-raid-v2-sign-and-wrap \
  SIGNING_INPUT PRIVATE_KEY SIGNED_COMMAND_OUTPUT OUTPUT_TX
```

`SIGNING_INPUT` uses schema
`trnm_paper_raid_finality_sign_and_wrap_input_v2` and supplies the chain ID,
32-byte lowercase-hex command ID, Hepta signer DID, nonce, gas/fee limits,
explicit outer-envelope issue/expiry milliseconds, and exact canonical
commitment CBOR hex. The envelope lifetime is limited to five minutes. The
command refuses any score/ranking/reward/economic eligibility flag.

The future V3 encoder remains available only as
`paper-raid-v3-pre-v7-artifact`. It emits a signed offline review artifact and
transaction-shaped bytes for fixture/protocol integration work. Its input
schema is `trnm_paper_raid_finality_pre_v7_artifact_input_v3`, and both its
artifact and result explicitly declare `broadcastable_on_app_v6=false` and
`required_consensus_app_version=7`. Do not broadcast that output to App v6;
activation requires a separately reviewed App-v7 binary, new genesis schema,
and export/new-genesis ceremony. V2 and V3 have distinct signed-command,
transaction, applied-record, state-key, and object-type domains; neither CLI
command accepts the other version's commitment bytes or silently upgrades
them. `assemble-and-verify` reports `domain_command_version` as `research_v1`,
`paper_raid_finality_v2`, or `paper_raid_finality_v3`.

`SIGNED_COMMAND_OUTPUT` is a strict, secret-free audit artifact containing the
canonical signed-command CBOR, canonical inner transaction, command and
commitment hashes, applied-record key, signer public key, and Comet transaction
hash. For the active V2 command, `OUTPUT_TX` is the exact canonical
outer-envelope bytes to broadcast to App v6. For the pre-v7 V3 artifact,
`OUTPUT_TX` is fixture/review material and must not be broadcast. The Hepta
queue endpoint must decode the signed CBOR with the vendored protocol and
recompare the complete sealed preparation; it must not trust the summary
fields. Both files are create-new mode `0600`; private key bytes are never
copied into either artifact.

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
