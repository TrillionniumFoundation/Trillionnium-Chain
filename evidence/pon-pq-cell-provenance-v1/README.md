# PCV1 signed Cell provenance — retained local experiment

**HOLD_NO_GO; no deployment or protocol activation.** New implementation:
\`formal/pon-nakamoto-v1/pq_cell_provenance.py\`, with adversarial tests
\`test_pq_cell_provenance.py\` and design in
\`docs/security/PQ_CELL_PROVENANCE_RESEARCH_V1.md\`.

Parent source PR #408 at
\`7cca6f76c5b6c7ac71bcccc1ce94da380360af40\`.
No parent consensus/W1, QTX1, legacy Ed25519, Chainwork, Hepta Final-use or
keys were modified by this PR.

## Executed observation

- Environment: Python 3.13.5, OpenSSL 3.5.5, Linux x86_64 kernel 6.18.55,
  \`overlayfs\` staged source copy; 5 tested code/test files' Git blob SHA
  identities independently checked against GitHub branch bytes.
- Exact command:
  \`python3 -m unittest -v test_pq_cell_custody.py test_pq_cell_provenance.py\`
- **25 passed, 0 failed, 2.473s**: 15 existing custody cases plus 10
  new full provenance cases. All signing and verification used real
  ML-DSA-65 via OpenSSL, with no stub provider.
- Console: [local-unittest.log](local-unittest.log).
  Machine-readable source/environment/count/scope:
  [local-qualification.json](local-qualification.json).

## Actual result and deliberate negative observations

The new verifier rejects a complete, internally consistent and signed
Merkle catalog whose content does **not** equal the exact named weight
digest in signed PCB1; a newly signed catalog cannot silently replace
the caller's pinned one. It independently rechecks the complete genuine
ML-DSA release signature and reviewer 2-of-3 signature identities,
rather than trusting the mere hash of an unverified claimed release
frame. Wrong network, family, parent, plan, generation, manifest,
release frame, prior head, content, signer, quorum, or expiry all reject.

The output is informational. The test names and proof checks do NOT
assert independent evaluator ownership, true current Hepta export
permission, public storage custody/retention, a production P2P service,
authenticated trusted state or chain authorization. The supplied
expected digests, current head and roster are explicitly **caller-owned
trust inputs**, not verified production owners. No whole-chain quantum
PoW security theorem, native consensus integration, hardware power-loss
or independent cryptographic audit is claimed.

**Remaining:** native audited PQ key custody, trusted model/Hepta release
anchors, streaming storage, independent evaluators, real P2P/DA,
quantum-work-fraction security and complete M00–M17 production
acceptance. Activation remains false.
