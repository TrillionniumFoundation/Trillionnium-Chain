# Pure PoN work statement and adversary model v1

This is the PN0/PN1 contract for the work packages authorized on 2026-10-27.
It freezes the subject of experiments; it does not qualify computational
hardness, change the active work profile or activate a network. The only
engineering sequence remains the [development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
Source input is Chain #498, commit `4b6b8a91b6dfe41fbd7f40f40b359d535c2c4251`.
PQ and DAA research have their own source receipts; an adjacent PR is not
implicitly included in this input.

## 1. Consensus authority and complete relation

Only a fully validated neural-work block may add chainwork. Stake, evaluator
votes, quality scores, signatures, availability attestations, elapsed time,
prover identity and storage bytes add zero chainwork. No hash-only work,
Hashcash fallback, BFT finality, trusted evaluator or TEE can satisfy a missing
neural relation. Hashing used inside W1, commitments and proof protocols is
not an independent block-eligibility rule. Existing W2-C experiments are not
eligible alternatives in this pure-PoN work package.

The existing PNH1 header is exactly 318 bytes. It fixes network, parameters,
parent, height, timestamp, target, miner, transaction root, State root,
receipt root, work task and nonce in its canonical encoding. Let `c` be
`H("challenge", header)`, using the original SHA-256 domain and LE length
framing. PNW1 is exactly 49,188 bytes: `PNW1 || A || B || C || t`, where
each 64 by 64 matrix is canonical row-major u32 little endian and every
word is below `q = 4294967291`. Reducing an out-of-range input is forbidden.

For each challenge, the exact bounded rejection sampler expands the four
64 by 8 / 8 by 64 factors `EL, ER, FL, FR` with labels 0, 1, 2, 3 and
counters starting at zero. At most 128 hash blocks per label are allowed;
exhaustion rejects the relation. Define `A' = A + EL*ER` and `B' = B + FL*FR`
over Fq. Compute every prefix tile in the native `bi,bj,bk,i,j,k` order,
including all 32,768 updated accumulator words. The streaming digest is
SHA-256 of `TRNM-PON-TRACE1\0 || c || all prefix words`; changing the
order, replacing it with a Merkle root, or sampling a subset changes W1.
The claimed product must equal the native reconstruction
`C = A'B' - (A*FL)*FR - EL*(ER*B') = AB` over Fq.

Task identity is `H("task", bytes(A), bytes(B))`. The sole lottery ticket is
`H("ticket", c, t)`, compared as the original 256-bit byte order against
the nonzero **branch-required** target. The complete relation includes the
canonical input checks, task binding, target comparison, bounded noise
generation, every transcript update and C reconstruction. The original
`trnm_crypto_primitives::pon_work::verify` is the executable relation.

This relation alone is not a block-validity proof. The original Node must
also validate the actual candidate parent, required target, timestamp/MTP,
signed task eligibility and availability window, all transactions, M06
execution and State/receipt roots. A future succinct W1 verifier must fit
inside that admission sequence; it must not turn a relation receipt into
`WorkCheckedPacket`, a valid parent, a spend or install permission.

## 2. Unique work identity and every available degree of freedom

The existing logical identity is `H("block", header, t)`. A repeated
presentation of that identity is one block, regardless of receipt encoding,
STARK blinding, witness serialization, peer address or signature randomness.
Proof bytes and proof randomness never enter the ticket, target, work
identity or work credited to the branch. Equivalent valid proofs cannot
create extra chances or extra cumulative work.

| Choice | Permitted freedom and required accounting |
| --- | --- |
| Nonce | The full u64 space is miner-selected; every changed header has a new challenge. Unsuccessful attempts count in cost measurements. |
| Miner, transaction ordering and roots | Legal header choices may be searched. They are not modeled as fixed unless the experiment explicitly freezes them. The resulting transactions and roots still need original execution. |
| Timestamp | Miner selects among timestamps accepted on the candidate branch. Local future deferral and MTP are not a global trusted time oracle. DAA simulations must retain physical time separately. |
| Parent and private forks | Attacker may mine, withhold and reveal different valid branches, including during a partition. The receiver recomputes required target and accumulated work from each ancestry. |
| A/B task | Only tasks eligible under the actual parent are accepted. An attacker may fund or influence tasks to the extent the real task policy permits. Sparse, zero, repeated, low-rank and structured cases cannot be removed from adversary costs merely because honest fixtures are dense. |
| Task preparation | Public task material may be preprocessed, compiled, cached, factored and amortized across attempts, workers and forks. Only challenge-dependent work must be fresh; a full replay receipt does not prove a lower bound on the attacker's algorithm. |
| Product C | Deterministic for A/B. Reusing AB is permitted if every challenge-bound transcript is still correct. Useful-result rewards and deduplication are separate from chainwork. |
| Proof representation | Any supported valid cryptographic representation proves the same fixed relation. Representation salt cannot create an additional work identity. Unproven proof types fail closed. |
| Sybil identities and transport | Arbitrarily many identities/addresses do not create CPU credit, storage credit, extra confirmation denominators or independence. Finite local service bounds are stated under bounded traffic and resource assumptions. |
| Hardware/parallelism | Optimized CPU, GPU, FPGA, ASIC, memory/time tradeoffs, batch algorithms and algorithmic improvements are permitted. One reference implementation's runtime is not the cheapest legal strategy. |
| Model selection/evaluation | An attacker may overfit public evaluations or withhold improvements. Quality and no-update decisions belong to the original model owners and cannot increase block weight. |

## 3. Cost model and security assumptions that remain open

Under the single equal-cost-class assumption the specification uses
`p(T)=(T+1)/2^256`, `w(T)=floor(2^256/(T+1))`, and adds the required
branch target's w exactly once. A lucky smaller digest earns no extra work.
At equal chainwork retain the current valid tip; height, receipt count and
lexicographic grinding do not break that tie. These are conditional rules,
not a proof that W1 has independent uniform outcomes or equal marginal cost.

An experiment must report `(task preparation, failed attempts, successful
W1, proof generation, proof verification, serialization, transfer, M06,
durable settlement)` separately and retain the total. CPU process time,
wall time, peak RSS, hardware, compiler, profiles, source, binary, target
and all timeouts are required. Cached and cold costs are separate samples.
Compare complete legal implementations on the same task distribution and
target; do not credit a prover's claimed FLOPs or use verifier effort as a
lower bound on producer effort. Cost ratios are observations, not security
parameters.

Classical adversaries may preprocess any public information before the
parent is known and adapt thereafter. A classical security argument needs
a defensible bound on the attacker's effective accepted-work rate relative
to honest participants, a network-delay model and validated lottery
assumptions. None is supplied by the work relation alone. A certificate can
establish computational correctness without establishing physical energy,
fresh training, minimum sequential time or useful model improvement.

Quantum adversaries may use coherent/reversible implementations of the
entire W1 predicate, amplitude amplification, quantum parallelism and
memory. No "hash is hard therefore neural work is quantum safe" assumption
is allowed. Cost reports must distinguish oracle queries, reversible gate
count/depth, logical qubits, error correction and physical time. Quantum
random-oracle security of the exact proof transcript is an additional
obligation; choosing a transparent STARK does not automatically establish it.
The current 256-bit hash also must be assessed per application (preimage,
collision, commitment and Fiat-Shamir soundness), not assigned a universal
128-bit post-quantum strength.

For a quantum DAA model, an assumed work cost proportional to
`sqrt(difficulty)` is a conditional query-cost model, not an implemented
quantum attack on this chain. A fixed-probability, variable-work candidate
needs a lower bound on joint challenge-bound neural units: if m units can
be computed in sublinear cost, weighting them by m recreates an inflation
problem. All unit seeds must bind the entire header and unit index; sharing
earlier units while grinding only the final unit, choosing an easy subset,
changing partitions or counting duplicates is forbidden. That candidate
remains unactivated until its relation, direct-sum assumptions, branch
rules, encoding, proof and empirical hardware costs are separately checked.

## 4. Availability, recovery and model scope

History and public submissions use the existing CPU domain and durable
operation history. Cooperative cancellation, Busy, Deadline and Unavailable
are local service outcomes, not consensus Invalid. An unknown paid crash
cannot refresh credit on restart. Logical SIGKILL/cold-reopen tests must be
labeled separately from physical power loss and disk-controller durability.
Continuous History stays unavailable when its original durable operation
cannot be authorized; volatile admission cannot replace that journal.

Cell storage is a content-addressed union of retained releases with explicit
replication, retention and repair obligations. Neither a magnet identifier
nor a proof of bytes guarantees future retrieval. Base/tokenizer/config and
every Cell in the selected release closure must be verified before an atomic
install through the original Hepta loader/FinalUse owner. A new transport or
PQ signature does not create install authority. No-update is an acceptable
measured outcome; fabricated quality gain is not.

## 5. Proof experiment and disqualification criteria

The [complete W1 zkVM prototype](../../../../formal/pon-nakamoto-v1/w1_zkvm/README.md)
calls the exact native relation with a fixed-size PNH1/PNW1 input and exposes
the exact header, trace, ticket, existing work identity and full C. Its
verifier must check the pinned guest image, real succinct STARK and expected
public header. It rejects fake, composite and Groth16 receipts. The journal
alone is not a proof. Parent/task admission and M06 remain with Node.

Fail the candidate if it omits any W1 relation, changes the lottery, permits
proof-randomness tickets, uses a hash-only fallback or receives chainwork
without the original parent checks. A complete but larger/slower proof is
an implemented negative result: it cannot pass 2A's **actual benefit** gate.
Native default integration, quantum soundness, hardness, model efficacy and
independent WAN service each retain their own acceptance verdict.
