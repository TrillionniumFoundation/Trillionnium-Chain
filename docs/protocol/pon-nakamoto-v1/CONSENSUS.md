# PoN consensus: open work competition and cumulative-work selection

Status: normative development requirements; proposed wire/profile, not activated.
Owners M00/M02; consumers M01/M03-M08/M13-M15. This contract supersedes PoCO as the
new-development consensus target, not the meaning of historical PoCO proofs.

## C1. State and security model

A full node independently validates every accepted block. There is no validator
membership list, weighted vote, leader rotation, QC, TC, joint seal or deterministic
finality in the new profile. Mining identity binds work and payout; one identity does
not equal one vote. A pool does not acquire privileged validity authority.

The target security argument is a Nakamoto common-prefix/chain-growth/chain-quality
argument under an explicitly qualified adversarial effective-work fraction, network
delay, validation service and work-generation assumptions. A nominal less-than-half
work fraction alone is not a complete proof. Timestamp grinding, selfish mining,
precomputation, GPU/ASIC advantages, task-choice shortcuts and withholding must enter
the actual assumptions. No universal number of confirmations or zero rollback risk
is claimed. Model-evaluator honesty is a separate assumption, never ledger hashpower.

Replicated state is keyed by block hash and includes application roots, economic
balances, model/reward state, work-profile parameters and branch-local replay floors.
Local state also retains validated header ancestry, cumulative work, data availability,
execution overlays, active-chain generation and crash-safe reorganization intent.

## C2. Exact candidate binding

A proposed header preimage contains version, genesis/chain identifiers, parent hash,
height, parameter-profile hash, timestamp, target, transaction/body root, application
post-state root, receipt root, contribution/availability commitments, miner identity,
payout commitment and attempt seed. The experimental widths/order/bounds and positive/negative vectors are now fixed in
[LEDGER_WIRE.md](details/LEDGER_WIRE.md) and its JSON registry; production acceptance remains separate.

Let template include EVERY miner-chosen field above, excluding only the work output
and proof. Let challenge = H(domain_challenge || canonical(template)). Let a qualified
work program produce a canonical unique work output y from that challenge and its
committed neural-task inputs. The work digest is H(domain_work || challenge || y).
The block identifier binds template and y, but NOT randomized proof encodings.
Proof bytes are a bounded witness of this fixed statement, not extra lottery nonces.

Changing parent, payout, body, parameters, timestamp, input/model or attempt seed
must require a fresh qualified expensive attempt. Merely hashing an unchanged trained
model beside a fresh nonce is forbidden. Binding fields as unused public inputs in
a SNARK is insufficient: the work relation and anti-shortcut analysis must make the
challenge affect the charged computation. Completed proof reuse under the identical
statement is retransmission, not additional work. Header/proof malleability must not
create multiple rewards or independent lottery outcomes.

## C3. Block admission

Process bounded decoding, known version/chain/parent, height=parent.height+1, exact
parent-derived target/profile and timestamp rules before expensive proof checks.
Verify the complete neural-work statement, digest <= target, producer/payout binding,
complete required block bytes, deterministic ordered application execution and all
roots. Failed verification consumes a bounded verification budget. Work alone cannot
make invalid transactions, absent model data or a mismatched state root valid.

A proof-valid header can be retained as header-only progress, but does not become an
executable active-chain tip until the entire required ancestry, body, work proofs and
application dependencies have been validated. Local overload or missing data is
Unavailable; bad proof/state is Invalid. Do not permanently blacklist a header just
because one peer returned corrupt or missing data. A miner cannot bypass mandatory
bounded expiry/refund/retention work by producing a more difficult block.

## C4. Work and fork choice

For the SINGLE admitted equal-cost work class and 256-bit uniform lottery contract:

    p(T) = (T + 1) / 2^256
    work(T) = floor(2^256 / (T + 1))
    chainwork(b) = chainwork(parent(b)) + work(expected_target(b))

Target is in [1, pow_limit], with pow_limit < 2^256. Use exact checked wide integer
arithmetic; the intermediate 2^256 must be representable. Chainwork is derived from
validated ancestry, never trusted from a peer or a header field. Work uses the required
target, not the observed lucky digest. Model quality, parameter count, stake, submitted
training-step counts and evaluator signatures do NOT multiply work.

The formula is conditional on the qualified lottery/work contract; it does not prove
that any arbitrary neural routine has uniform independent outcomes or equal cost.
Heterogeneous work classes are not mixed by an invented quality conversion factor.
Changing the work relation requires a separately reviewed new profile, difficulty
mapping and context-bound activation; no hot-swapped evaluator selects the easier rule.

Among fully validated branches, adopt one with strictly greatest chainwork. At equal
work keep the current valid tip (first locally admitted candidate if none); the next
strictly heavier branch resolves the tie. Do not award work for lexicographic grinding,
shorter latency or more peers. Height alone never selects the chain. A stale block
has no active-chain mint; its independent model artifact may be resubmitted for one
contribution reward under the surviving chain's deduplication rules.

## C5. Difficulty and time: exact reference design

Genesis fixes interval N>=16, target spacing tau>0, initial target, pow_limit,
median width 11 and factor clamp 4. The experimental values are N=16, tau=10 seconds, median11 and clamp4;
[devnet-v1.json](../../../config/pon/devnet-v1.json) fixes all test-network parameters.
These are not approved production deployment values.
For candidate height h not divisible by N, inherit parent.target. At h=k*N, use
ancestor timestamps at h-1 and h-N (N-1 intervals), desired=(N-1)*tau and
observed=max(1, timestamp[h-1]-timestamp[h-N]) using checked signed difference.
Clamp observed to [ceil(desired/4), 4*desired]. Then:

    target_h = clamp(floor(parent.target * clamped_observed / desired), 1, pow_limit)

All ancestors are on the candidate branch. Genesis supplies height zero. Reject wrong
targets rather than trusting a sender's work total. Timestamp must exceed the median
of up to the previous 11 branch timestamps. A header too far ahead of protected local
time is deferred and rechecked, not declared permanently invalid; future-skew allowance
and receiver-clock assumptions require deployment qualification. Reorg recomputes DAA
from the new branch. Time-warp/burst tests may require a revised DAA before launch;
this reference rule is not claimed attack-optimal. No silent minimum-difficulty reset.

## C6. Confirmation, economics and effect boundary

M08 exposes included block hash, observed best tip, depth, cumulative-work delta,
profile and active-chain generation. A confirmation policy requires both its named
depth and work threshold; these are probabilistic risk controls, not QC finality.
Genesis fixes reward maturity and transaction/action confirmation policies. A local
consumer may wait longer, but cannot rewrite consensus validity or make a stale
receipt current. New RPCs must use included/confirmed/reorged, not unconditional finalized.

A valid heavier chain is never rejected merely because its reorg crosses a local
six-block, reward-maturity or pruning threshold. Missing deep undo data triggers
bounded verified replay/state sync while effects remain fenced. No administrator
checkpoint or BFT committee silently restores deterministic finality. See recovery.

## C7. Upgrades and liveness

Difficulty periods and model generations are not PoCO validator epochs. New consensus
rules are explicit protocol releases/activation contexts, not automatic outcomes of
model voting or an LLM proposal. Incompatible peers refuse them; conflicting networks
remain visibly distinct. There is no automatic old-PoCO or hash-only fallback.

An improvement in model quality is NOT mandatory per block. Qualified evaluation,
retention or consolidation work on already admitted public artifacts must have an
always-available, bounded genesis-defined work source when new contributions are absent.
Its computational hardness must be qualified too: cached answers and zero/low-rank
workloads cannot provide cheap tickets. Otherwise useful-task exhaustion is a liveness
blocker, not permission to fabricate learning gains or silently switch algorithms.

## Executable contract binding

The full relation is [W1](details/WORK_PROFILE.md), encoding/application is [L1](details/LEDGER_WIRE.md),
and disk branch/reorg is [S2 and the native owner](details/STATE_RECOVERY.md). The existing Python reference
remains a small arithmetic model; the new ledger oracle uses actual signed transactions,
real work verification and SQLite. Neither is a qualified native public-network node.
