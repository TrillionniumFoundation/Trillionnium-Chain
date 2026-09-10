# TRNM Native PoCO Consensus and Settlement v1

Status: **binding development direction; protocol details remain under active review**  
Scope: native block consensus, task validity, consumption settlement, rewards, challenges, and finality evidence

## 1. Canonical direction

TRNM is developed around its own **Proof of Consumption (PoCO)** protocol. PoCO is not a detachable application feature and it is not delegated to a third-party consensus engine.

The canonical native path is:

```text
signed transaction
  -> trnm-mempool admission
  -> trnm-chain-node proposal
  -> trnm-chain-validator independent execution and vote
  -> 2/3+1 native quorum
  -> trnm-state / trnm-pouw state transition
  -> state root, block finality, and verifiable receipt
```

The block-consensus and settlement layers are intentionally coupled by protocol-native types, deterministic execution, state commitments, challenge rules, and finality receipts.

## 2. PoCO layers

### 2.1 Native ordering and finality

The native validator protocol is responsible for:

- authenticated validator identity;
- proposal formation and deterministic transaction ordering;
- independent command authentication and execution;
- transaction-root and state-root recomputation;
- vote durability and anti-equivocation;
- round change and proposer progress;
- quorum formation with at least `2/3 + 1` voting power;
- commit propagation, recovery, and finality receipts.

A validator must never vote for a proposal that it cannot authenticate and execute locally to the same roots.

### 2.2 Proof of Consumption validity

PoCO validity is responsible for deciding whether a task output is eligible for settlement because it was actually consumed under the protocol rules. The minimum settlement unit is:

```text
committed output
  + canonical reveal
  + authorized consumption receipt
  + replay-safe accounting
  + challenge/resolve window
```

Generation alone does not create a reward claim. A settlement claim must be funded, bounded, attributable, and independently verifiable.

### 2.3 Economic settlement

PoCO economics must preserve value conservation. Rewards are paid from explicit client funds, escrow, governed fee pools, or another committed source. A receipt proves attribution and consumption; it must not silently mint value.

## 3. Core state machine

The v1 task lifecycle remains:

```text
OPEN
  -> ASSIGNED
  -> COMMITTED
  -> REVEALED
  -> CONSUMPTION_OPEN
  -> CHALLENGED | SETTLED
  -> RESOLVED | EXPIRED | SLASHED | REFUNDED
```

Every non-terminal state must have a deterministic exit path. Deadlines, refunds, stake release, slashing, and challenge resolution must be driven by committed block height and protocol state rather than local wall-clock decisions.

## 4. Canonical objects

### 4.1 Output commitment

An output commitment binds:

- chain ID;
- task ID and assignment ID;
- worker identity;
- output hash;
- reveal commitment;
- protocol version;
- nonce and expiry boundary.

### 4.2 Output reveal

A reveal binds:

- the committed output;
- canonical tokenizer identity and version when token accounting is used;
- output token count;
- output root or span commitment;
- optional provenance evidence;
- the worker signature and transaction nonce.

### 4.3 Consumption receipt

A consumption receipt binds:

- task, assignment, worker, and consumer identities;
- output hash;
- billing or settlement window;
- consumed amount and optional consumed-span proof;
- consumer class and policy version;
- strictly monotonic consumer nonce;
- consumer signature.

The canonical replay key is at least:

```text
(chain_id, task_id, consumer_id, output_hash, settlement_window)
```

## 5. Validator acceptance rules

A validator accepts a PoCO transaction only when all applicable rules pass:

1. canonical decoding and version checks;
2. chain, sender, role, key, signature, nonce, and expiry checks;
3. object-version preconditions;
4. deterministic gas and fee limits;
5. task-state transition validity;
6. escrow and issued-supply conservation;
7. output/reveal/receipt binding;
8. consumer eligibility and anti-self-consumption rules;
9. replay and duplicate-credit rejection;
10. challenge, resolve, expiry, refund, and slashing rules;
11. deterministic event and state-root production.

Unknown transaction or proof types fail closed.

## 6. Consensus safety requirements

The native protocol must maintain these invariants:

- no two conflicting blocks may finalize at the same height;
- a validator may not sign conflicting votes for one height and round;
- quorum certificates must bind chain ID, validator set, height, round, and block hash;
- validator-set transitions must be committed and activated at deterministic heights;
- recovery must never roll committed state backward silently;
- replayed commands, votes, receipts, and nonces must be rejected;
- identical ordered inputs must produce identical state roots and events;
- malformed, oversized, unauthenticated, or resource-exhausting inputs must fail closed.

## 7. Liveness requirements

Liveness claims require evidence for:

- proposer failure and round change;
- one Byzantine or offline validator within the fault bound;
- process crash before and after durable vote/state writes;
- minority and half-split partitions;
- partition healing and convergence;
- validator restart, replacement, and key rotation;
- bounded mempool pressure and admission backpressure;
- multi-host latency, packet loss, clock skew, and sustained load.

Loopback success is development evidence only and must not be presented as public-network proof.

## 8. Threat model

The minimum threat model includes:

- forged or altered transactions and votes;
- validator equivocation;
- stale or conflicting proposals;
- command, nonce, receipt, and proof replay;
- self-consumption and Sybil consumption;
- duplicate credit and token-count inflation;
- malformed proof payloads;
- state-store corruption and partial writes;
- peer flooding, slow clients, hot-object contention, and state growth;
- compromised worker, consumer, operator, or validator keys.

## 9. Anti-fraud requirements

PoCO settlement must not ship without:

- no billable self-consumption;
- bonded, governed, or reputation-bearing billable consumer classes;
- per-task and per-consumer caps;
- deterministic duplicate suppression;
- frozen metering/tokenizer semantics by protocol version;
- challenge bonds and bounded challenge windows;
- explicit slashing and refund destinations;
- auditable governance changes and activation heights.

## 10. Module ownership

- `trnm-node`: native proposal, voting, recovery, block finality, and orchestration;
- `trnm-finality-types` / `trnm-finality-verifier`: portable vote, quorum, proof, and receipt verification;
- `trnm-pouw`: PoCO lifecycle, verification, challenge, resolve, and settlement rules;
- `trnm-state`: versioned state, balances, governance state, replay state, and roots;
- `trnm-executor`: deterministic conflict grouping and parallel-execution research;
- `trnm-mempool`: bounded admission, deduplication, priority, and backpressure;
- `trnm-rpc`: stable transaction and query surfaces;
- `trnm-worker-agent` / `trnm-cli`: worker, consumer, and operator workflows.

## 11. Acceptance evidence

A capability is considered implemented only when it is exercised through the native node and validator path and has reproducible evidence for:

- deterministic multi-validator state roots;
- transaction and object inclusion proofs;
- quorum and finality verification;
- replay and equivocation rejection;
- crash and restart recovery;
- partition safety and post-heal convergence;
- value conservation;
- bounded CPU, memory, disk, and network behavior;
- end-to-end latency and throughput under stated hardware and workload profiles.

## 12. Release boundary

The repository remains under active development. No public-testnet or mainnet readiness claim is valid until the native PoCO consensus, validator lifecycle, key management, slashing, networking, state synchronization, observability, indexer, and long-duration fault tests are closed by reproducible gates.
