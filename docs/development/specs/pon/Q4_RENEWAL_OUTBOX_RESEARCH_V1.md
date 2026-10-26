# Q4 renewal lost-ACK and reorg reconciliation — bounded research v1

**Authority:** subordinate development experiment under `TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`, not a replacement plan. Only `formal/pon-nakamoto-v1/q4_renewal_outbox_research.py` uses its `q4_outbox_*_v1` SQLite namespace. **Not a native M05/M07 owner, signed lease verifier, network dispatcher, `FinalUse` token, consensus revision, miner, new Q4 codec, automated authority, or deployed recovery.**

## Problem isolated

A source and requester can pre-sign the exact Q4 tag22 transaction while the old lease is still eligible, but delayed inclusion, a lost HTTP/TCP acknowledgement, fork reorganization and restart cannot prove whether a real external submission already occurred. The dangerous naive behavior is to treat `Unknown` as `NotDispatched`, reset nonce/fee/time budgets, re-sign, or automatically use Maintenance when a particular selected lease is revoked. Any replacement signed transaction must be a **new independently authorized operation**, not a recovery mutation.

The research outbox receives an externally supplied **full 1,187-byte PNX1/tag22 transaction** as opaque bytes. It verifies the length, the exact PoN `H("tx-id", [raw])` content identity and only caller-declared context/window/sequence *syntax*. The synthetic regression bytes are intentionally not signed. It does **not** verify Ed25519, current lease, actual source renewal, rights, material availability, on-chain inclusion, source withdrawal or the client's signature over its purported receipt. Only existing owners may perform those operations.

## Finite journal state and transitions

`RenewalIntent` commits an independently supplied 32-byte operation ID, network/parameters/genesis, observed parent, current and proposed lease digests, active generation, source/requester sequences, signed window and full raw transaction. In one fresh journal, an operation ID and an exact transaction ID each have **at most one** immutable intent. The implementation rejects trying to relabel a packet under a new operation and trying to substitute different signed bytes under the same operation. A hash-based row ID cannot create new authorizations.

After durable `prepare`, the application must persist `DISPATCH_UNKNOWN` **before** any separately owned I/O submission. It is a conservative sticky record: the external send might not happen, might succeed, or might return a lost acknowledgement. `dispatch_unknown` is not a send command or permission. Once persisted, the same operation cannot acquire another dispatch fence even after `Included`, `Confirmed`, `Reorged`, `Expired`, `Unavailable` or cold reopen. Recovery is read-only observation of the **original transaction ID** until an authorized owner establishes a separate new operation. This trades automatic retries for fail-closed anti-duplication; it is not a liveness solution by itself.

`ChainObservation` records a caller-supplied active-generation, tip, height, membership class and exact upstream receipt digest. The class label is **untrusted local research metadata**: `OBSERVED_CONFIRMED` does not mean an independently validated client confirmation, and `OBSERVED_REORGED` cannot rewind an already attempted physical submission. Generation is monotonic per operation. The original client must verify packet bytes, inclusion in a fully validated active chain and an installed depth+work policy; reconnect must re-read actual generation/confirmation instead of trusting this journal's event labels.

Every event is finite, append-only, context-bound, sequence-numbered and predecessor-hash-linked. `BEGIN IMMEDIATE`, `synchronous=FULL`, create-only identities, single-dispatch unique index, bounded max intents/events, post-COMMIT `UnknownEffect`, and an O(record count) cold-open audit detect local inconsistency and preserve uncertain outcomes. A hash chain in a local SQLite file **does not** protect against privileged database rewrites or assert physical power-loss durability. Filesystem pathname checks are not race-safe against hostile local processes. No storage budget external to the finite row count is claimed.

## Executed qualification and open native boundary

Run from `formal/pon-nakamoto-v1`:

```sh
python3 -m unittest -v test_q4_renewal_outbox_research.py
```

The tests explicitly exercise lost ACK, durable pre-/post-COMMIT cuts, delayed receipt, confirmation then reorg, expiry, cold reopen, duplicate operation/packet, different SQLite connections, monotonic generations, wrong context/length/type, forensic tampering and event/intent quotas. They use local synthetic public byte strings. No actual requester/source signature, `Node::admit`, W1 proof, P2P listener, real network partition or independent operator executes.

**Production integration remains blocked:** M05/M07/kernel.operations must consume *actual signed Q4 tag22 transactions and current source/withdrawal facts* under the one original durable owner; persist a submission pre-effect fence with externally installed authority; submit through the real bounded transport and reconcile `Unknown` via independent client history and surviving/reorganized chain; preserve local effect history across deep reorganizations. Run real 32-slot retention, renewal at the last legal height, two independent signers, lost ACK, disk crash and material loss with the original native W1 Maintenance path. This research file cannot be used as an authority adapter or a new second ledger.

## Canonical observation audit hardening (research continuation)

The local journal now independently validates the complete fixed 113-byte
`ChainObservation` grammar when an `OBSERVED_*` event is appended **and**
when all historical events are replayed on cold open. It refuses zero generation,
zero observed tip, zero evidence/receipt digest, an absent included-block digest
for Included/Confirmed, a nonzero included-block digest for
Reorged/Unavailable/Expired, mismatched kind tags, truncated or mutable byte
buffers, and unknown event kinds. The original event hash and generation-order
checks remain required. An internal call to `_event` cannot bypass this validation.

Two negative suites cover malformed internal append and cold SQLite observations
whose checksum was deliberately recomputed to match their corrupted fields.
Recomputing a local row digest is **not** forging an authenticated chain receipt;
the experiment proves a canonical decoder invariant, not tamper resistance
against an administrator who can rewrite both the SQLite bytes and hash chain.

These changes were published on the existing draft research branch as
`9c848875dfdf5756af8292b3f13e808269260c38` and
`774fc4bb08a4162be24a56e759a9718d11b961c8`. The exact-branch Python
outbox tests still need execution in an environment possessing this full source
checkout; the local separately reconstructed observation-codec probe passed.
Real Q4 signatures, original-owner journals, independent PoN client proofs,
WAN lost-ACK handling, uninterrupted mining and production admission remain
strictly unqualified. No old Q4, Maintenance, W1 or DAA consensus rule changed.

## 2026-10-26 schema-bound replay and independent-W1-receiver follow-up

Retain the upstream canonical-observation validation unchanged. A separate
incremental hardening checks exact v1 SQLite schema objects during cold audit,
including the partial UNIQUE dispatch fence, and rejects additional SQLite
triggers, views, tables and downgraded indexes before trusting stored events.
The negative tests create each foreign object on disk and require a closed
refusal. This guards research schema drift, not privileged on-disk rewrites or
independent authenticated confirmations.

The unchanged existing non-ignored all-32-slot native Maintenance revocation
fixture additionally feeds all original real W1 packets through a second fresh
SQLite Node, independent block-by-block admission, full wire decode and
required-work/depth confirmation. That receiver cold-reopens separately and
must preserve the producer-observed result. Same-admin fixtures do not
establish independent operators, and these added Rust assertions remain NOT_RUN
until a source-matched Rust toolchain can execute them. No Q4/W1/DAA signed
bytes, consensus validity or production activation changes.
