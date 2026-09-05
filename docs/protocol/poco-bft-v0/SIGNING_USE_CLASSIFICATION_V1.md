# PoCO-BFT signing-use classification v1

Status: Stage-1 foundation, inert

Audit base: `7cd808b391142bb86187eb1ffc947a8f878dd839`

Production activation: `false`

This inventory classifies validator-adjacent private-key and signing uses
before the remote-signer migration. It is a code audit, not evidence that the
listed paths are safe for production. The only production-facing addition in
this change is the public-facts-only
`trnm-poco-node::PocoNodeRemoteSignerRoleBindingsV1` boundary.

## Required role split

| Role | Permitted purpose class | Current runtime truth |
| --- | --- | --- |
| P2P identity | authenticated session challenge, hello, finished, frame identity and relay origin | Lab still reuses the consensus key; migration not active |
| Consensus | vote, timeout vote, proposal and old/new-set handoff votes | vote/timeout journal request is typed; proposal/handoff journal and remote adapter are absent |
| Operator/recovery control | runtime evidence, planned restart, RecoveryReady and RecoveryStart | existing Lab wire values still verify against consensus keys; migration not active |

The three profile references and three public keys must be distinct. A remote
service endpoint reference may be shared because it identifies routing rather
than signing authority. Endpoint and profile references are produced only by
hashing bounded public descriptors under different SHA-256 domains; the raw
descriptors are not retained. The types cannot prove that operator-supplied
descriptor semantics are free of credentials or private material. That policy
remains the responsibility of the future authenticated resolver, which is not
implemented or activated here.

## Default production-facing boundary

`trnm-poco-node/src/remote_signer_roles_v1.rs`:

- imports no Ed25519 private-key implementation;
- accepts only role-specific public keys, nonzero profile references and
  nonzero endpoint references;
- binds the consensus profile to the exact committed validator-set public key;
- rejects public-key or signer-profile reuse across roles;
- has a bounded exact encoding with magic, schema, ordered role tags, a frozen
  purpose-profile digest and checksum;
- exposes typed vote and timeout-vote commands derived from canonical sign
  intents; proposal and handoff remain classification values only; and
- exposes no producer, credential, network client or `sign(bytes)` API.

The Cargo truth values keep remote-signer runtime activation and all three
runtime role migrations false. These types must not be interpreted as a signer
lease, HSM session, SafetyRules authority or process activation capability.
The P2P and operator public-key wrappers currently reject zero bytes but do not
perform strict Ed25519 point parsing; strict parsing is an explicit activation
blocker, not evidence supplied by this foundation.

## Raw consensus key owner in the LAN Lab

`trnm-poco-lab-validator/src/config.rs` is the one ordinary Lab configuration
owner. It:

- accepts `secrets/<validator-id>.pk8` from the sealed Lab manifest;
- parses the fixed Ed25519 PKCS#8 seed;
- stores `ed25519_dalek::SigningKey` in `LoadedValidatorConfig`; and
- exposes `LoadedValidatorConfig::signing_key()`.

That package is explicitly marked `production_candidate = false` and
`production_consensus_activation = false`. The raw key is still cloneable and
is still used across role classes, so the LAN Lab is not a remote-signer or
key-separation proof.

## P2P identity uses currently backed by the consensus key

These are protocol/runtime uses, not merely fixtures:

- `transport.rs`: challenge, hello and finished signatures; the session owns a
  cloned `SigningKey`;
- `frame.rs`: authenticated frame encoding;
- `consensus_mesh.rs`: mesh connection state owns a cloned key;
- `relay.rs`: relay-origin signatures;
- `consensus_runtime.rs` / `continuous_runtime.rs`: pass the loaded key into
  the mesh and transport paths.

They must migrate to `P2pIdentityRemoteSignerProfileV1` and a separately
reviewed typed P2P command protocol. This change intentionally does not allow a
generic byte signer as a shortcut.

## Consensus uses currently backed by the consensus key

Runtime or authoring paths:

- `crypto.rs`: `LabEd25519SignatureProducer`, which receives the journal-issued
  typed `SignatureRequestV0` for vote and timeout-vote roots;
- `continuous_runtime.rs`: proposal preimage sealing and direct proposal
  signature production;
- `consensus_runtime.rs`: loaded-key plumbing for the journal producer and
  proposal runtime;
- `bootstrap_material.rs`: Lab bootstrap proposal and vote authoring; and
- `degraded_window.rs`: degraded-window statements plus test vote/QC/TC
  authoring.

Fixture-only consensus signing also exists in `collector.rs`, `loop_driver.rs`
and `wire.rs`. The independent `trnm-consensus-signer-journal` production code
contains no private key; its `SignatureProducerV0` accepts only a
crate-issued `SignatureRequestV0` over `CanonicalSignIntentV0`. Its
`tests/sqlite_journal.rs` test producer owns a `SigningKey`. The
`trnm-consensus-crypto` private key is confined to its unit-test module.

The current canonical sign intent covers vote and timeout vote. Proposal
and old/new-set handoff signing remain classified purposes only. No public
proposal or handoff sign command exists until a complete canonical intent,
persist-before-sign journal schema, exact replay rule and durable Safety witness
can be reviewed together.

## Operator and recovery-control uses currently backed by the consensus key

Runtime/control paths:

- `consensus_report.rs`: signed consensus-run report;
- `network.rs`: signed network-smoke runtime evidence;
- `runtime_evidence.rs`: signed metrics and final-state evidence;
- `startup_rejection.rs`: signed startup-rejection evidence;
- `process_event.rs`: signed process-event chain and planned handoff events;
- `signed_replay_archive.rs`: replay archive and terminal seal;
- `fleet_barrier.rs`: fleet Ready/Start control statements;
- `epoch_handoff_evidence.rs`: signed epoch-handoff evidence;
- `restart_cut.rs`: RestartPrepare/RestartCut control statements;
- `restart_catchup.rs`: catch-up provider/target messages;
- `recovery_barrier.rs`: RecoveryReady and RecoveryStart statements; and
- `restart_parked_ack_protocol.rs`: ParkedAck statement from the loaded config.

Fixture/store-only private keys also occur in:

- `fleet_barrier_evidence.rs`;
- `recovery_barrier_store.rs`;
- `recovery_zero_delta_store.rs`;
- `restart_park_store.rs`;
- `restart_parked_ack_store.rs`; and
- `restart_protocol.rs`.

The existing RecoveryReady/RecoveryStart verifier resolves each signer through
the validator set and therefore still authenticates the consensus public key.
Moving those statements to the operator/recovery key requires a versioned wire
and verifier change; merely swapping the local signer would make valid
statements unverifiable. This foundation consequently exposes the operator
profile but no active operator/recovery signing command.

## Other signing keys that are not validator consensus keys

`workload_corpus.rs` generates short-lived application operator/client keys to
author the bounded workload corpus and records that application private keys
are neither retained nor deployed. AI-native candidate crates contain
deterministic `SigningKey` values only in their unit tests. The legacy
`trnm-node` CLI accepts application/operator command key files; it is not the
PoCO validator consensus-key configuration and is outside this migration.

## `trnm-poco-node` legacy/test boundary

Default node modules contain no operational private-key configuration. Raw
keys remain in these bounded categories:

- `lab-validator-runtime` modules:
  `deployed_lab_process2_recovery.rs`, `deployed_lab_recovery.rs`,
  `native_h1_ordinary_takeover.rs` and archived authenticated-genesis paths;
- `lab-validator-runtime-test-support`:
  `native_h1_ordinary_test_support.rs`;
- `recovery-process-test-support`:
  `trnm-poco-timeout-signing-kill-helper.rs` and its process matrix;
- the non-buildable archived recovery helper source; and
- `#[cfg(test)]` fixtures in `external_node_checkpoint.rs`,
  `native_proposal_p_host.rs`, `recovery_tests.rs` and G2 real-E2E support.

No one of those paths is reclassified as a production remote signer by this
change.

## Next migration checkpoints

1. Version P2P handshake/frame verification around the committed P2P public
   key, then remove consensus-key transport signing.
2. Add proposal and old/new-set handoff intents, persist-before-sign journal
   events, exact replay and durable Safety witnesses; only then introduce typed
   sign commands or accept them in a producer.
3. Version operator/recovery wire values around the committed operator public
   key and typed Ready/Start/Restart commands.
4. Implement an authenticated profile/endpoint resolver and remote signer with
   generation fencing and an external monotonic watermark. It must never
   expose generic `sign(bytes)`.
5. Require strict Ed25519 parsing for every configured role public key and bind
   the resolved signer public key back to the exact profile digest.
6. Remove PKCS#8 loading and `SigningKey` ownership from
   `LoadedValidatorConfig` only after the Lab has typed adapters for every use
   above.
7. Bind the remote signer generation and all three public profiles into the
   whole-node checkpoint before enabling any timer, proposer or ingress path.
