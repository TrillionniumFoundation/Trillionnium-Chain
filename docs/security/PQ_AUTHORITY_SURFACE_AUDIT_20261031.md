# Trillionnium-Chain PQ authority surface: first-pass source audit (2026-10-31)

**HOLD / NOT A COMPLETE AUTHORITY MAP / NOT A PRODUCTION-SECURITY CLAIM.**

A first-pass research scan should not treat every \`Ed25519\` import as a deployed exploit, or every ML-DSA verification as an authorized effect. The [source scanner](../../scripts/ci/pq_authority_surface_scan.py) inventories Rust sources under \`trillionnium/crates/*/src\` with explicit line numbers, file SHA-256 digests, known owner hints and **unreviewed** indicators.

\`\`\`sh
python3 -m unittest discover -s scripts/ci -p 'test_pq_authority_surface_scan.py' -v
python3 scripts/ci/pq_authority_surface_scan.py --summary-only
python3 scripts/ci/pq_authority_surface_scan.py > /tmp/pq-authority-sources.json
\`\`\`

## Known starting points (not evidence of deployment)

| Source | Observed cryptographic boundary | Missing end-to-end proof |
| --- | --- | --- |
| \`trnm-types/src/transfer.rs\` | Classic Ed25519 transfer address/signature | Which native profile, if any, actually gives this path ledger authority; PQ-only path must reject downgrade |
| \`trnm-service-settlement/src/engine.rs\` | Two registered classical signer keys on bilateral settlement | Trace registration, settlement effect, replay, rollback and production reachability |
| \`trnm-research-protocol/src/command.rs\` | Research command has Ed25519 authorization | Determine if downstream command creates execution/upgrade authority |
| \`trnm-research-protocol/src/hepta_handoff.rs\` | Hepta V1 validates Ed25519 and research authority set | V1 must never authorize PQ-only Hepta FinalUse or install |
| \`trnm-research-protocol/src/hepta_handoff/pq.rs\` | New ML-DSA-65 V2 candidate and external pin | Actual roster freshness, operation-journal CAS, FinalUse, crash/reorg recovery |
| \`trnm-data-availability/src/cell/discovery.rs\` | Classic provider record verification | Whether any live PQ-only provider admission trusts legacy V1 |
| \`trnm-data-availability/src/cell/discovery/pq.rs\` | ML-DSA provider record V2 | Current externally rooted key directory, revocation, live dispatch |
| \`trnm-pon-node/src/ingress.rs\` | Legacy classical session constructor has PQ-profile denial in #627 | All alternate transport/CLI/bootstrap entrypoints and actual native owner routing |
| \`trnm-crypto-primitives/src/pq_auth.rs\` | Canonical ML-DSA verification primitive | No role, nonce, spend, governance or release is granted by a correct signature alone |
| \`trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/application_v6.rs\` | PQ account/application candidate | Canonical nonce, state/reorg, origin and live effect propagation under configured PQ profile |

These are verified source-path locations in the candidate branch lineage, not ten exhaustively analyzed authority flows. Imports or signature validation do not independently prove active network permission or exploitation.

## What the scanner guarantees and does not

- It fails on missing curated critical source files, symlink Rust source/directory, oversized source, invalid UTF-8 or unstable read length. New Rust signature-indicator files appear under \`unreviewed-source-hit\`, not as approved PQ routes. Fixed test fixtures include missing-path, unknown Ed25519/PQ code, symlink and size/encoding negatives.
- It reports source hash, line numbers and both classic/PQ indicators, but cannot infer which functions grant an effect; can miss aliases, native C/Python, externally linked libraries, macro expansion, indirect verification, dynamically loaded plugins and wire-level downgrade. It includes test-only and dead code.
- At each actual authorization sink the reviewer still must collect: selected profile; caller; message/domain; authoritative key provenance; generation/revocation; replay and state transition; crash/reorg/total-DB rollback behavior; legacy/fallback decisions; exact native tests; independently retained evidence.
- **PQ-only release condition:** every effect-authorizing path is either PQ-authenticated with independent current trust root and test-proven transition semantics, or rejects the PQ profile before creating an effect. A classic+PQ \`OR\` policy cannot satisfy this goal. Classic+PQ \`AND\` is defensible only with a verified migration policy and both signatures bound to the same exact statement.

This is a first audit artifact to make the missing inventory visible, not a claim that all entrypoints were found or all hold gates are closed. The original whole-chain [six-gate claim guard](WHOLE_CHAIN_PQ_CLAIM_GUARD_20261031.md) remains **HOLD** regardless of this scanner's result.
