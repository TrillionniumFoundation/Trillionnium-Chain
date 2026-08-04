# 01 — System Model and Threat Model

## 1. System model

PoCO-BFT v0 replicates a deterministic state machine across a fixed weighted validator set during each epoch. Blocks form a parent-linked tree rooted at a synthetic genesis block at height `0`. Heights start at `1`; views start at `1` and increase monotonically within an epoch.

Each validator has a stable `validator_id`, one Ed25519 consensus public key for the epoch, and a positive integer effective voting weight. The canonical validator set is immutable within the epoch and is authenticated by `validator_set_hash`.

The network is partially synchronous:

- before an unknown Global Stabilization Time (GST), an adversary may delay, reorder, duplicate, drop, or partition messages for an unbounded duration;
- after GST, messages exchanged between correct online validators are eventually delivered within an unknown finite bound;
- local timers are advisory pacemaker inputs, not sources of consensus truth.

Authenticated transport is REQUIRED at the node layer for peer attribution and operational defense. Consensus safety, however, MUST depend on the cryptographic signatures and domain-bound message contents, not on the transport connection alone.

## 2. Fault model

A validator is Byzantine if it deviates arbitrarily, including by equivocating, withholding messages or payloads, signing invalid data, cloning or rolling back a signer, or operating multiple processes with the same epoch key and inconsistent journals.

For normal operation in epoch `e`, safety assumes Byzantine effective voting weight `B_e` satisfies:

```text
3 * B_e < W_e
```

where `W_e` is the total effective voting weight committed for that epoch. During an epoch handoff, this inequality is assumed separately for the old set and the new set. The protocol does not turn a violation of that assumption into safety.

Crash faults include process termination, host reboot, transient I/O errors, and loss of volatile state. Durable state corruption, restoration of a stale disk image, key cloning, or signing-journal rollback MUST be treated as Byzantine behavior unless the signer detects it and fails closed.

## 3. Cryptographic assumptions

Safety assumes:

- SHA-256 is collision and second-preimage resistant for all consensus uses;
- Ed25519 signatures are existentially unforgeable under chosen-message attack;
- public keys and validator identifiers are correctly bound in the epoch validator-set commitment;
- private keys are not exposed or cloned without detection;
- `CEV0` has one accepted canonical byte representation for each logical value;
- implementations reject malformed, non-canonical, unknown-version, and wrong-domain messages before counting their signatures.

Cryptographic agility requires a future protocol version. A node MUST NOT negotiate a different hash or signature algorithm inside protocol version `0`.

## 4. Honest-validator obligations

An honest validator MUST:

1. maintain monotonic durable `epoch`, `view`, lock, `highQC`, and signing decisions;
2. sign at most one normal vote for a given consensus identity tuple;
3. execute and validate the complete block payload before voting;
4. verify the proposal signature, justify QC or TC, active-set hash, protocol version, parent, roots, and deterministic timestamp bounds;
5. follow the safe-vote and lock-update rules exactly;
6. refuse to count duplicate signers or weights from any other validator-set commitment;
7. fail closed on arithmetic overflow, storage uncertainty, unknown protocol versions, ambiguous encoding, or safety-state corruption;
8. retain or delegate sufficient finalized history, validator-set data, and evidence data for the configured proof and accountability windows.

## 5. Adversary capabilities

The adversary may:

- schedule, replay, delay, reorder, duplicate, and selectively deliver valid messages;
- create arbitrary invalid messages and transport identities;
- control Byzantine validators and coordinate their votes, timeouts, proposals, consumption relationships, and bond operations;
- cause process crashes, restarts, disk-full conditions, truncated WAL records, and temporary state unavailability;
- propose valid-but-adversarial transaction orderings and payloads;
- withhold old blocks, application data, or state chunks from particular nodes;
- attempt long-range attacks after old keys or bonds are no longer slashable;
- manufacture or reciprocally exchange apparent consumption where certificate-admission policy permits it;
- exploit differences between parsers, integer implementations, clocks, and upgrade binaries.

## 6. Threats and required mitigations

### 6.1 Equivocation and cloned signers

Domain-bound signatures, a durable persist-before-sign journal, and objective double-sign evidence are the primary controls. A cloned key with divergent durable state is Byzantine; remote signing or an HSM can reduce this risk but is a P2 deployment concern.

### 6.2 Parser and cross-chain attacks

Every signed or hashed preimage uses `CEV0` and a fixed domain. It binds the genesis hash, chain identifier, protocol version, epoch, validator-set hash, view, message kind, and message-specific contents. Reusing a signature across chains, epochs, views, sets, message kinds, or protocol versions MUST fail verification.

### 6.3 Network partitions

Partitions may halt progress. They MUST NOT cause two correct validators to finalize conflicting blocks under the fault assumptions. After healing and GST, liveness additionally requires enough correct online weight and a functioning pacemaker.

### 6.4 Crash and rollback

WAL replay may reconstruct non-safety operational state. It MUST NOT overwrite a newer sign journal, lock, `highQC`, epoch, or view. If durable records disagree or their ordering cannot be proven, the validator MUST stop signing and require operator recovery.

### 6.5 Invalid execution and data withholding

An honest validator MUST possess the entire block payload, deterministically execute it, and verify all committed roots before voting. A QC therefore attests that more than two thirds of active voting weight validated the payload under the assumptions. It is not a perpetual, general-purpose data-availability guarantee for historical clients; archival/erasure/availability mechanisms remain separate work.

### 6.6 Long-range and weak-subjectivity attacks

An unbonded historical validator set may later collude without an effective penalty. Light clients therefore require a recent trusted checkpoint and must fail closed after the trusting period. Self-authenticating validator-set chains are insufficient once the trust assumption is stale.

### 6.7 PoCO manipulation and cartel behavior

Consumption Certificates establish a signed attribution under the frozen schema; they do not prove social usefulness, unique human demand, honest market pricing, or independence of the parties. Maturity, decay, per-relationship caps, provider caps, deterministic snapshots, and bond capacity limit amplification. They do not eliminate collusion or cartel risk. Related-party rules, economic constants, and anti-reciprocal-consumption policy remain `UNDECIDED` for mainnet and must be resolved before the corresponding activation phase.

### 6.8 Denial of service and resource exhaustion

Wire-size limits, bounded collections, duplicate rejection, peer-level authentication, rate limits, and state-sync validation are required. The consensus safety claim does not imply availability under unlimited CPU, memory, disk, bandwidth, or adaptive-DoS pressure.

### 6.9 Upgrade divergence

Nodes accept only the protocol version authorized by finalized epoch state and activated through the joint handoff certificate. An unknown or unauthorized version causes fail-closed behavior. There is no automatic consensus rollback.

## 7. Safety claim

Subject to the cryptographic, deterministic-execution, durable-signing, and Byzantine-weight assumptions, two correct validators cannot finalize conflicting blocks, and therefore cannot finalize different blocks at the same height. This is a conditional protocol claim to be modeled, implemented, tested, and independently reviewed; this P0 document is not itself a proof.

## 8. Liveness claim

After GST, the protocol is expected eventually to finalize new blocks if:

- at least `quorum(W)` correct voting weight is online and mutually reachable;
- payloads and execution dependencies are available;
- timeouts grow enough to exceed actual post-GST delay and processing time;
- a correct leader is eventually selected;
- no epoch transition waits on an unavailable required old-set or new-set quorum;
- all correct validators run the authorized compatible protocol version.

No deterministic BFT protocol provides unconditional liveness in a fully asynchronous network. A valid next validator set whose quorum is offline can safely stall the joint handoff.

## 9. Deferred threat work

Production remote-signer hardening, key rotation ceremonies, encrypted transport profiles, peer-discovery security, state-sync sampling, adaptive-corruption analysis, formal economic modeling, privacy-preserving certificates, mainnet parameter calibration, and external audits belong to P2–P4. None may be inferred from the P0 freeze.
