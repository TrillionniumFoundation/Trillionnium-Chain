# PPH1 local replay / crash observation journal (research-only)

**HOLD_NO_GO.** This is a subordinate M04 offline experiment stacked on the exact PR #417 parent, commit c3b2e4c79c463f782f2785134da4c1e929e655e2. All production activation and consensus flags remain false. No historical PoN, W1, difficulty, QTX1, Chainwork, native Rust M04 host, Hepta final-use or deployment change.

## Threat: channel binding does not imply one-use

The preceding PPH1 purpose=6 signed observation checks genuine ML-DSA-65, trusted sender and receiver keys, network/genesis/profile, current TLS exporter, generation/sequence/nonce and <=60-second expiry. An attacker replaying the exact signed message *within* its original valid TLS session may still reach a receiver more than once. A restarted process might lose an in-memory replay table.

This increment adds LocalPeerReplayJournal. It independently verifies the complete PPH1 signature and TLS-channel-binding arguments on every call, then uses SQLite WAL/FULL with BEGIN IMMEDIATE to consume a (network, signer key) monotonic generation/sequence record atomically. Exact identical retried frame returns ALREADY_RECORDED. A changed frame at the same position, lower generation/sequence or invalid signature/channel never creates a second FIRST_RECORD. Only a higher sequence or verified higher generation is a new local observation. A producer may not force a trusted next generation: verification inputs still must be supplied by an actual independent owner.

The local table is STRICT and WITHOUT ROWID; open and every write fail closed on foreign schema, triggers, views and weakened primary keys. The cap is 1,024 peer entries. Database path symlinks reject. SQLite integer range is deliberately restricted to positive signed 63-bit for persisted generations/sequence. The journal never issues Node admission, Chainwork, model-release, custody-reward or Final-use authority.

## Actual adversarial experiments

- Real OpenSSL ML-DSA-65 sign and verify, then duplicate same original signed PPH1 from one process; first record then already recorded after cold reopen.
- Eight separately spawned OS processes and SQLite connections concurrently call the exact same verified statement: one FIRST_RECORD and seven ALREADY_RECORDED.
- Actual process os._exit(0) after durable commit but before caller ACK; cold reopen sees already recorded, never issues second first observation.
- Different signed nonce at same sequence, stale generation, stale sequence and invalid signature or TLS exporter reject without invalid state mutation.
- Foreign view, destructive trigger, weakened table, symlink DB path reject before use.
- **Intentionally retained global counterexample:** clone initialized SQLite to two independent filesystem paths before consumption; both accept the same signed PPH1 as FIRST_RECORD. This is not a passing global anti-replay result. Only an independently anchored and coherently replicated identity/spend owner can close that remaining blocker.

## Executed evidence and scope

On Linux x86_64, Python 3.13.5, OpenSSL 3.5.5, SQLite 3.46.1, the combined original mTLS plus replay suite ran:
cd formal/pon-nakamoto-v1 && python3 -m unittest -v test_pq_mtls_probe.py test_pq_peer_replay.py

**19 tests passed, 0 failed**. Both added source Git blobs exactly match the executed files, as do the unchanged parent C probe, PPH1 and PQ signature envelope. Source identities and raw output are in evidence/pon-pq-peer-replay-v1/. The reported SQLite FULL/WAL receipt is local process-crash behavior on the observed filesystem, NOT physical power-loss or independent hostile storage evidence.

## Open production gates

- Real product Rust M04/M15 peer admission and independent trusted identity/generation owner.
- Actual TLS session receives PPH1 bytes on wire; current mTLS probe and PPH1 signer are coordinated in the experiment rather than one deployed host.
- Cross-host replicated replay/rollback protection, storage custody and epoch rotation; clone negative currently demonstrates the gap.
- Real certificate lifecycle/HSM, independent WAN/eclipsing, zero-RTT/resumption, Sybil and cost admission.
- Account, transaction, wallet, model, mining and PoN quantum effective-work safety, independent cryptographic review and release qualification.

Keep the entire Chain post-quantum claim false until those are closed by real owner-bound, independent execution.
