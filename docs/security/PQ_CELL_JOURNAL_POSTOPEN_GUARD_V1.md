# PQ Cell M09 local replay-journal post-open hardening (P0 research)

Development continuation of Chain #468 at f408fc65f99c2b5445c75e0595e9208c887f7015. NO ACTIVATION. No change to W1/PNW1, Chainwork, Ed25519 ledger, QTX1, signed PCR1/PCA1 bytes, model adoption or Hepta FinalUse.

## Verified local counterexample

Original file Git blob 5dabec97985cebe3de8feff51089267bd8650aea inspected sqlite_master only in OfflineOneUseJournal.__init__. After it opened, an external SQLite writer could create an AFTER INSERT trigger that deletes the new signed-retrieval observation. The original record method returned FIRST_RECORD without an existing row. Reproduction: the single negative test test_post_open_trigger_cannot_delete_new_record FAILED as expected (Reject not raised). This is a local one-use accounting bug, not a break of ML-DSA or PoN work.

## Scoped implementation

- New databases use exclusive/no-follow create mode 0600. Existing empty/foreign-schema, symlink leaf, hardlink leaf, group/world-readable and missing/replaced file identities fail closed. Caller still owns the parent namespace.
- Before every read/insert/retry acknowledgment, acquire BEGIN IMMEDIATE and re-audit the exact table-only DDL, WAL and FULL settings, plus pinned (device,inode) identity, *inside the transaction*. Unexpected post-open trigger, table, or file replacement rolls back.
- Keep original signed PCR1 proof verification ahead of the journal, never replace it with a boolean or trust caller-provided text. New tests mock the cryptographic result ONLY to stress actual SQLite transaction and filesystem behavior.
- No old observations are dropped, no consensus-authority object is produced and no network-wide nullifier is claimed.

## Actual local test scope

Focused run: PYTHONWARNINGS=error python3 -m unittest -v test_pq_cell_custody_journal_hardening.py : **12 passed / 0 failed**, Python 3.13.5, SQLite 3.46.1, Linux overlayfs. Eight distinct connections raced one challenge: one FIRST_RECORD, seven ALREADY_RECORDED.

Compatibility observation: the 15 retained PCQ1/PCR1 tests plus 12 new tests all passed (27 total), invoking real OpenSSL 3.5.5 ML-DSA-65 signatures. HOWEVER this run used a local, noncommitted reconstruction of the original TPQ1 pq_envelope interface because a complete GitHub checkout was unavailable. It is NOT an exact upstream cryptographic suite, native Rust or independent qualification. The focused journal tests themselves do not invoke signature verification.

Known limitations: hostile same-UID ancestor replacement/races, in-place data modification, snapshot clone/rollback of all durable anchors, independent multi-host replay, real WAN and physical power loss remain OPEN. A local SQLite observation cannot authorize Chainwork, Hepta FinalUse, model release or storage payment. Keep independent acceptance and production_activation false.

Next: exact full checkout with original pq_envelope and inherited suites; native M09 journal owner and durable external checkpoint; authenticated Chain release/Hepta export; M00–M17 genuine PQ node/wire and PoN quantum work-security qualification.
