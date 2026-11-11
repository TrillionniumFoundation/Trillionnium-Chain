# Account authorization and development boundary

Status: **development hardening / production admission remains closed**.
This increment continues the existing #847 integration candidate from
`df927b6ffaecff293b9e9428e3ba516f47cd101a`. Its implementation and execution
receipts must be attributed to their own committed source. The
[sole development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [whole-chain claim guard](WHOLE_CHAIN_PQ_CLAIM_GUARD_20261031.md) remain
authoritative. No deployed network, asset, account, key or service is migrated
or activated by this change.

## 1. What the ordinary path actually does

The ordinary CLI requires `--development`. Without an explicit PQ application
configuration it selects classical development accounts. A valid Ed25519
envelope can debit a sender, credit a recipient, consume a nonce and pay a fee
in that test ledger. These are real state transitions, even though the fixed
unit has no monetary value. This path remains available for development and
tests; its existence must be included in any inventory of authorization paths.

An explicitly selected PQ application returns through its own verifier and
owner. A malformed PQ configuration, missing native feature or invalid PQ
packet does not retry as a classical transaction. The ordinary application
configuration is distinct from the transport configuration: the research
`pq-tls-serve` path can carry a classical development application inside PQ
transport. PQ TLS alone therefore does not identify PQ account authorization.

These distinctions follow the actual
[CLI dispatch](../../trillionnium/crates/trnm-pon-node/src/main.rs),
[application executor](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs),
[local PQ entry](../../trillionnium/crates/trnm-pon-node/src/pq_application_local.rs)
and [TLS entry](../../trillionnium/crates/trnm-pon-node/src/pq_tls_cli.rs).

## 2. A shared execution-time boundary

`Config::check_account_profile` is the shared check for account authorization.
Every currently implemented account profile must retain all three existing
development fields, with their exact JSON types and values:

| Field | Required value |
| --- | --- |
| `production_activation` | Boolean `false` |
| `not_mainnet` | Boolean `true` |
| `coin_atomic_unit` | String `test-unit-no-market-value` |

A missing field, `null`, wrong type or other value returns
`ACCOUNT_DEVELOPMENT_SCOPE_REQUIRED`. The check runs at execution and state-root
boundaries, including an empty block, before mandatory transitions or rewards
can acquire application effects. It is not limited to initial configuration
loading or CLI parsing.

The genuine private PQ owner still selects and validates its own configuration.
NPQ2–NPQ6 retain their complete owner-bound configuration digest, and the older
QTX1 owner retains its existing policy checks. A selected PQ owner cannot become
classical by deleting its public selector. In the classical branch,
`account_authorization_profile` and any `native_pq_*` field must be absent.
Explicit `null` is not absence. An orphan, unknown or incomplete PQ declaration
is rejected rather than interpreted as an invitation to use Ed25519.

The Node uses the same check for initialization, reopening and live namespace
operations. Public owner wrappers that accept already constructed Settings
check them before opening their application owner. Continuous startup preserves
its original authorization and budget order: where the owner must reserve and
account for a failed attempt before Settings exist, those journal effects
remain. Rejection does not promise to erase legitimate failure accounting.

This is a configuration and execution boundary. It does not prove that an
attacker can modify trusted in-process Config, nor does it protect against
arbitrary replacement of the program. The immutable signed parameters and
existing owner metadata remain the sources of protocol identity.

## 3. Which profiles may participate

**The production-qualified profile set is empty in this candidate.** None of
the following research paths can be made production-qualified by a JSON flag,
a successful signature check, a TLS handshake or a passing unit test.

| Account authorization | Permitted current use | Production admission |
| --- | --- | --- |
| Classical Ed25519 development | Explicit development CLI, test fixtures and their bounded research owners | Refused |
| QTX1 / PQG1 account research | Explicit pinned PQ account owner and applicable migration contract | Refused |
| NPQ2–NPQ6 / ML-DSA-65 | Explicit matching PQ application, network and storage owner | Refused |
| CPQ1 ML-DSA-65 / ML-DSA-87 parameter candidates | Retained parameter experiments and verification observations only | Refused; no current activation API |

Classical authenticated and public-development transports may have explicitly
configured non-loopback research listeners. They remain test networks; this
change does not claim that every classical listener is loopback-only. Operator
and release-owner routes that dispatch before the ordinary CLI's
`--development` check remain subject to their own owner contracts and the
shared application/Node checks. A general command-line flag is not their
authorization source.

A future production profile needs an independently authorized deployment
transition that binds the complete application, peer, governance, release,
recovery and work configurations. The current registry does not supply that
transition. See the existing
[cryptographic profile contract](CRYPTO_PROFILE_V1_20261104.md).

## 4. Old accounts, authorizations and snapshots

Old classic state is not upgraded by renaming a directory, editing profile
labels, replacing a key field or loading it with PQ settings. Existing stores
remain bound to their original schema, parameters, genesis and owner policy.

The existing restricted migration path can take a real admitted source
checkpoint, verify a separately pinned prior PQ key registry, preserve supported
balances, nonce floors and liabilities, and create a distinct PQ research
network. Imported accounts remain locked until their required PQ CLAIM is
verified. Unsupported source rows cause refusal rather than silent omission.
The implementation is in
[migration.rs](../../trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/migration.rs)
and the real
[Node checkpoint handoff](../../trillionnium/crates/trnm-pon-node/src/store/pq_migration_inventory.rs).

Production migration still requires evidence that cannot be manufactured by a
local import: the prior key registry existed before compromise, the source
checkpoint is independently final, the old assets and authorizations are
retired, all effect-bearing authorization domains are covered, and rollback of
local state cannot rewind an independently held revocation or consumption
frontier. Possession of a classical key after it is forgeable cannot establish
its original owner. A successful restricted import is not a waiver of these
requirements.

## 5. Recovery and upgrade behavior

The existing Node cold-open checks compare actual schema, `parameters`,
`genesis`, `pq_network_owner_v2` and the selected witness binding. PQ application
settings require a PQ owner backend; classical network helpers refuse a PQ
owner. The new shared check also refuses damaged development scope and orphan
PQ declarations before the ordinary store is created or reopened, and during
live namespace checks. A damaged current owner is classified as local structural
failure and requires that owner to stop. Invalid startup input and remote
diagnostic text cannot manufacture this local integrity classification.
Observation-only snapshot preparation and legitimate failed-operation accounting
retain their existing bounded effects; this is not a promise of zero temporary
file or journal activity across every research entry point.

Upgrading this code does not silently rewrite historical signed bytes or
storage. Valid historical development configuration remains byte-compatible.
An invalid configuration that previously slipped through the classical guard
now fails closed. Restoring a snapshot still requires the same authenticated
owner context and any independently held witness; the new guard does not
create a new monotonic witness or certify common-backup recovery.

## 6. How participants compare algorithm and profile identity

The current protocol uses fixed grammars and owner-selected identities, not
algorithm negotiation from untrusted messages. NPQ versions have separate
wire prefixes and signing domains. The existing
`pq_accounts_v2::crypto_profile_id` maps the validated real owner to its fixed
algorithm, encoding, network, parameters, genesis, protocol version and scope.
The PNQ2 policy binds the matching network context, roster, generation and
resource limits. Peers must use that pinned context; an advertised profile ID
cannot replace it or select a weaker verifier.

No new field is inserted into old messages in this increment. A future version
that changes a signed domain, algorithm or stored schema requires a fresh
namespace and its own compatibility, recovery and negative tests. Profile
agreement establishes agreement on rules, not that those rules are already
production-qualified or that PoN work is quantum-secure.

## 7. Required evidence for this change

Validation must exercise the actual executor and Node owners:

- A valid classical development transfer still performs the expected debit,
  credit, nonce and fee effects.
- Damaged development fields and orphan PQ markers reject the same transfer
  and an empty block before mandatory/reward effects or callbacks.
- Invalid Settings cannot create a fresh ordinary store; the same defect
  cannot modify an existing store during cold open.
- A warm owner cannot continue after its account scope is corrupted.
- Existing PQ/classical refusal, real migration/CLAIM/cold-open and existing-owner
  recovery controls continue to pass on the same committed source.
- Locked Cargo graphs, formatting, strict Clippy, source-integrity negative
  controls and Markdown links are checked without weakening existing gates.

The execution record must retain failures and name its actual source, binary,
toolchain and command. Earlier #847 runs and other PR lineages are background
evidence only. A scoped pass closes the stated development boundary; all
remaining production, migration-authority, independent-recovery and whole-chain
PQ qualifications stay open until their own evidence exists.
