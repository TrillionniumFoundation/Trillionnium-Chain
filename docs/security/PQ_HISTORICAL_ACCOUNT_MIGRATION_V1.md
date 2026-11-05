# Historical accounts: inventory, precommitted migration and seed recovery

Status: development and isolated recovery research; **HOLD**. This contract
extends the [sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It does not activate a new genesis, retire a live source network, establish
whole-chain PQ security or grant recovery authority.

## Source composition

This continuation starts from PR #688 at
`5c070abeb61d0ea8702fa94fffe9330d1699119c`. The separately inspected PR #706
head is `c09e681b043cad8141a659ca40a9b19a2eca9d5e`. The final composition
also preserves integration head `d0737cf5434894ce47fad8082376fc417313c2cb`,
including its retained-evaluation/checked-weight work and generated Cell inputs,
and the later `bd2777f9cc74df10ba07ae8202584ed0fb90a519` Legacy reorg
observation/source-pin increment. The subsequent checkpoint recovery, release
authority and transport changes at
`245146c7d2e6f7dfcda463f6a7dd342d4d7ca818` are also preserved, followed by
the quantum research and bounded admission composition
`c156c2310346d1367b8f9b1111171f412b5ffce2`.
The #688 and #706 histories are divergent development lineages. #706 includes older native migration owners and extra
complete-state nonce checks; #688 includes Application V6 and subsequent
integration work. A successful #706 workflow is not evidence that #688 executes
the same owner or contains every #706 check.

The current migration constructor explicitly creates a distinct research
genesis. It does not implement an in-place, reorg-sensitive transition of a
running classical network. Its trust-selected registry is configuration, not
proof that a classical owner registered a PQ key before compromise. See
[native migration](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/migration.rs)
and the existing [native account boundary](PQ_NATIVE_ACCOUNT_OWNER_V1.md).

## A. Establish the complete asset and obligation scope first

The new [read-only native inventory](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/migration_inventory_v1.rs)
accepts independently selected network, genesis and checkpoint pins plus the
complete checkpoint material. It checks header identity, parameters, the entire
state root and the existing completed-state/conservation rules before counting
every row. A header preimage and a matching state root alone do not prove W1,
canonical source history, finality or the completeness of the selected network.

| Source data | Inventory behavior | Consequence |
| --- | --- | --- |
| Account rows | Count every identity, balance, nonzero balance and nonce floor | A zero balance does not erase an identity or nonce |
| Task, quota, release, reward rows | Keep independent counts and amounts, including zero rows | No netting or omission of old execution/settlement records |
| Issued supply | Run the original full conservation check | A self-declared zero cannot hide positive recognized liabilities |
| Zero current-model sentinel and exact inert metadata | Identify explicitly | No inference from a project label or version string |
| Other rows, including debt, revocation, execution and active-model references | Count all; bound only the diagnostic key examples | Unsupported semantics require investigation, not an empty-ledger result |

`NoLedgerCarryFound` means that this exact ledger contains only the enumerated
inert metadata and zero issued supply. `PreservationRequired` covers every
account or obligation row, even zero-valued records, and every unclassified row.
Neither result authorizes activation. The report always names the scopes the API
cannot inspect: other ledgers/debts, pending settlements, in-flight execution,
external dependencies, independent revocation/retirement records and actual
source write retirement. It accepts no Boolean that can waive these checks.

No deployed source state or external obligations inventory was supplied for
this continuation. Therefore situation A is **not established**. If a complete
operational inventory later establishes A, use a separately selected PQ genesis
and retain the former network as a read-only archive. The actual write owner,
configuration rollout and dependency owners must all agree on the retirement;
creating a new database by itself does not retire the old one.

## B. Precommit, snapshot, restrict, CLAIM, then activate

The existing native sequence is retained:

1. Independently select a registry that was authenticated while the old
   authorization remained trustworthy. Bind the source network/genesis, stable
   source account, exact PQ public key and generation. An offline dual-possession
   experiment already requires both signatures over the same complete statement;
   it is not a historical registration authority.
2. Fix the source checkpoint and complete source scope. Enumerate balances,
   nonce floors, tasks, rewards, other monetary obligations and nonmonetary
   revocation/execution state. Unsupported source records must remain unresolved
   until their original owners have an explicit preservation/retirement rule.
3. Import supported rows into the restricted new namespace. Accounts cannot
   spend before CLAIM. A complete funds check must not be interpreted as a
   complete migration of every application or external obligation.
4. CLAIM verifies the pinned precommitted PQ key and possession of the new PQ
   key over the same bound command. Its payload/context binds the anchor,
   checkpoint, source state, account, balance, source nonce, permissions, current
   operation nonce and destination context. Installation and nonce consumption
   remain one original M06 transition.
5. Keep stable identity and key-generation history. Rotation retires the previous
   generation; old key bytes remain available to reject reuse. Replenishing an
   account does not lower its nonce or remove its key history.

After a classical key is forgeable, an attacker can sign with that old key and
with an attacker-selected PQ key. Requiring both signatures at that time cannot
establish the original owner's identity. Neither a frozen balance snapshot nor
the new PQ namespace repairs that missing historical premise.

### Complete-state nonce consistency

The #706 checks missing from #688 are retained here with fresh native controls.
Let `n0` be the imported source nonce, `n` the current account nonce and `g` the
retained PQ generation. The required lower bounds are:

| Account origin | Required nonce floor | Bound origin |
| --- | --- | --- |
| Claimed import | `n > n0` and `n >= n0 + g` | Source checkpoint and retained import record |
| Initial account in the genesis descriptor | `n >= g - 1` | Private initial-account set derived from the same sorted inputs as the descriptor |
| Account created by REGISTER | `n >= g` | Registration consumes nonce 1 before any rotation |

Arithmetic is checked. No caller Boolean can classify a registered account as
a genesis account. A separate native counterexample demonstrated that applying
`g - 1` to REGISTER accounts incorrectly accepted a retained generation-1
authority with nonce 0. Real registration and rotation now also guard that case.
Each CLAIM, REGISTER and rotation consumes an account nonce, so a state that
retains their authority while rewinding these nonce floors is inconsistent. Complete-state validation must
reject it before a snapshot/recovery caller can treat it as valid.

These are necessary lower bounds, not proof that the complete transaction
history occurred. They cannot detect restoring an entirely coherent older
database together with its older authority rows. That threat still needs an
independently retained monotonic root covering account/effect state. The current
PNQ2 witness covers its documented network-owner tables, not every balance,
settlement, CURRENT or FinalUse state. The preserved checkpoint-store increment
adds strict independently pinned journal cold recovery, but Node/M06 do not yet
bind their complete account/effect state to that journal owner.

### Deletion, restoration and cross-activation reorganization

No public account-deletion operation is added. Zero balance must not authorize
discarding stable identities, nonce floors or retired-key records. Any future
account compaction/import must preserve those records under a versioned schema;
an account recreated by funding cannot revive a retired generation. A coherent
full-store rollback remains a separate external-root requirement.

The current distinct-genesis constructor cannot reorganize across an activation
point in the source chain. A future in-place protocol must specify these rules
before it can be activated:

| Event | Required shared rule |
| --- | --- |
| Importing old blocks | Validate by their explicit historical profile; do not grant present effects |
| Current spending/execution | Require the selected current authorization and revocation state |
| Canonical removal of a binding or migration root | Derive the same frozen/reconciliation state from the same canonical input on every node |
| Retired key or consumed recovery identity | Preserve its local/external effect retirement under the existing owner contract |
| Reconciliation completion | Bind the new canonical source, generation and preserved obligations before any new effects |

An individual node's memory that it once observed activation cannot create a
different nonreorganizable consensus boundary. Consensus branch selection and
the monotonic safety of effects need separate, explicit owners and reconciliation.
This continuation implements no such activation switch and claims no closure of
that protocol requirement.

## C. Original EdDSA seed: isolated recovery research

The primary source is Baldimtsi, Chalkias, Roy and Sedaghat,
[Post-Quantum Readiness in EdDSA Chains](https://eprint.iacr.org/2025/1368),
the full FC 2026 version last revised 2026-03-20. The
[official conference program](https://www.ifca.ai/fc26/program.html) lists the
paper. Its abstract reports 6.2 seconds proving, 2.3 seconds verification and
a 5.4 MB proof with Ligetron. These are author-reported measurements, not results
of this repository's tests.

The official [PQChain source](https://github.com/SoundnessLabs/pqchain/tree/598cdff516c3086487a173d7d9f9af2830e04a32)
at `598cdff516c3086487a173d7d9f9af2830e04a32` identifies itself as work in
progress and not production-ready. Its
[README](https://github.com/SoundnessLabs/pqchain/blob/598cdff516c3086487a173d7d9f9af2830e04a32/README.md)
reports a different proving figure: **5.4 seconds**, averaged across 100 runs
on a 12-core MacBook Pro M4 with 24 GB RAM. Verification and proof size are
2.3 seconds and 5.4 MB. Do not attach that hardware/methodology to the paper's
6.2-second abstract figure without checking the full experiment. The README's
34 MB memory field is not an independently verified complete-process peak RSS.

The [circuit](https://github.com/SoundnessLabs/pqchain/blob/598cdff516c3086487a173d7d9f9af2830e04a32/sdk/cpp/examples/PQChain/pqchain.cpp)
uses a 32-byte seed as its private witness. It checks Ed25519 public-key derivation
from `SHA512(seed)` and checks `hx = SHA512(msg || seed)`. Recovering an elliptic
curve scalar does not directly disclose the original seed. A recovery protocol
still needs the full public statement to bind the new PQ key and all migration
context; merely proving knowledge of some seed for an old public key is not an
authorization to change arbitrary account state.

The new [isolated public-input component](../../formal/pon-nakamoto-v1/pq_seed_recovery_v1.py)
only constructs and checks the public research request. It has no seed input,
proof verifier, verifier callback, production queue, ledger writer or authority
type. A structurally consistent request is explicitly unverified. Its tests
exercise message/identity/context/size rejection, not the ZK relation, PQ
possession verification, spent-nullifier durability or actual recovery.

### Required integration boundary

The complete versioned statement must bind network/genesis, crypto and
derivation profile, stable legacy account/public key, source and migration roots,
destination PQ algorithm/parameters/key, operation nonce, expected account
generation and state, validity interval, circuit/verifier identities and exact
proof parameters. The seed proof's public message and the new key's PQ
possession signature must bind that same complete statement.

A future qualified recovery owner must check the account is still restricted
and its source/migration roots are current before admitting expensive work, then
recheck immediately before its single atomic commit. The one-use identity is
the account/migration operation, not randomized proof bytes. Identical retries
must observe the same result; conflicting requests for the same operation must
refuse. Consumption, retired generations and preserved obligations must survive
crash, restoration and canonical reconciliation. A seed proof cannot recreate
balances already spent or stolen.

Proof work belongs in a separate bounded owner with per-proof/aggregate byte
limits, pending-count and concurrency limits, CPU/memory/wall deadlines, output
limits and charged failure attempts. Expiry, cancellation and verifier failure
produce no authorization. Cache only immutable proof facts with full input and
verifier/parameter identities; never cache current account permission. Seed
material stays exclusively in the local proving process and must not enter
requests, command-line arguments, ordinary logs or telemetry.

### Open cryptographic and deployment gates

The following are not supplied by the public-input implementation:

- Full paper proof review, including knowledge soundness, zero knowledge and
  Fiat-Shamir behavior in the stated quantum model.
- Exact circuit, compiler, verifier, launch configuration and security-parameter
  reproduction; transparent setup alone does not establish a particular PQ bit
  level. The PoC uses SHA-256 commitments and must be reviewed with its actual
  quantum collision/search assumptions and query budgets.
- Independent target-host proof/verification measurements with malformed proof,
  cancellation, memory exhaustion and concurrent recovery loads.
- Coverage of actual historical wallet derivations and high-entropy seed custody.
  A 32-byte field proves neither entropy nor that the wallet retained that seed.
  Expanded-secret-only, scalar-only, mnemonic-derived and hardware-wallet cases
  need their own explicit compatibility decisions.
- Authentic source scope and prior theft accounting; source retirement,
  canonical reorganization handling and durable one-use/effect-state roots.

The [compact reproduction record](../../evidence/pq-historical-migration-20261104/README.md)
separates executed native/parser controls from these remaining obligations.
