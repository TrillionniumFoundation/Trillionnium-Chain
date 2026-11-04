# Whole-chain post-quantum security — strict HOLD gate (2026-10-31)

This is a **research-only security-claim guard**, not a PQ-128 attestation, production consensus gate, cryptographic proof, or authorization mechanism. The native development candidate retains its explicit NO ACTIVATION boundary.

Run from the repository root:

    python3 scripts/ci/test_pq_chain_claim_guard.py -v
    python3 scripts/ci/pq_chain_claim_guard.py
    python3 -m unittest discover -s scripts/ci -p 'test_pq_authority_surface_scan.py' -v
    python3 scripts/ci/pq_authority_surface_scan.py --summary-only
    python3 -m unittest discover -s scripts/ci -p 'test_pq_external_rollback_oracle.py' -v
    python3 -m unittest discover -s scripts/ci -p 'test_pq_quantum_daa_scenarios.py' -v

The guard checks actual negative authority and activation assertions in the source-controlled project boundary, mainline and devnet configuration, and the existing PQ source corpus; it checks the canonical ML-DSA research frame size and unqualified legacy transaction ceiling. It returns a deterministic **HOLD / UNQUALIFIED** report with process status 0 only when the current protected negatives are intact. Unsupported promotion, silent classical fallback, missing source, invalid or duplicate JSON fields, symlink substitution and an introduced PQ-128 W1 guest claim are refused with process status 2. A green test of this guard never means the network is PQ-safe.

## Six separate acceptance gates

| Gate | Current boundary | Evidence needed to close |
| --- | --- | --- |
| Authorization | NPQ6 account/task and PNQ2 transport are separate. [Hepta #4497 at f28af9b](https://github.com/TrillionniumFoundation/hepta-private-ci/commit/f28af9b7700a61fbbcdcc121521cb879297d5e31) routes explicitly configured `ml_dsa65_v2` ordinary Cell/initial FinalUse consumers and Codex turn/start through canonical PQ authority. Untagged compatibility remains classical; current Objective/RunStart V1 and inspected HTTP automation constructors retain classical authentication; generic production grant consumers accept injected authority and need separate composition qualification. Complete governance, release, recovery and composed deployment are unqualified. The earlier [ML-DSA V2 research verifier](HEPTA_PQ_HANDOFF_V2_20261031.md) has separate historical scope; Cell provider discovery V2 is ML-DSA. | Trace every authority-producing entry, including governance, release and recovery, to a current externally pinned PQ trust root; reject cross-profile downgrade and revoked generations on real effect paths. |
| Proof PQ-128 | Current Node acceptance uses the complete [native PNW1 verifier](../../trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs); the [isolated succinct-proof experiment](../../formal/pon-nakamoto-v1/w1_zkvm/README.md) is not a Node backend. Neither establishes whole-chain PQ-128 qualification. | For the native path, fix the complete relation, actual verifier and per-purpose hash assumptions, assess worst-invalid-input cost and obtain independent cryptographic review. Before accepting any succinct-proof backend, additionally pin guest/compiler hashes, commitment/FRI/Fiat–Shamir parameters, recursion, final verifier and a quantum-soundness argument. Groth16/fake receipts cannot satisfy PQ-128. |
| Quantum mining and fork choice | Current cumulative-work/DAA incentives have no full adversarial quantum lower bound. | Test cheapest valid complete W1, data loads, reversible oracle/uncompute, challenge amortization, Grover advantage, retarget/timestamp manipulation, reorganization and propagation on equal attack budgets. |
| Migration and rollback | Classical ownership transition and local durable ledgers do not automatically resist total database rollback. The [research reference](PQ_EXTERNAL_ROLLBACK_WITNESS_REFERENCE_20261031.md) and the explicit [native PNQ2 witness component](PQ_NETWORK_DURABLE_WITNESS_V1.md) have separate evidence. The native component covers three PNQ2 tables under an independent-witness-state assumption; it does not cover all Node/Hepta state or provide a trusted deployed remote service. | Bind early PQ ownership, historic liabilities, old nonce floors, all effect-bearing state, cross-reorg recovery, an independently administered monotonic anchor and independent cold-restart adversarial tests. |
| Capacity and invalid input | Research TPQ1 signature frame is 3487 bytes; original devnet maximum transaction remains 2048 bytes. | Full native NPQ6 block and mempool capacity, invalid-signature CPU cost, wire/relay amplification, p95/p99, RSS and recovery under fixed hardware/traffic constraints. |
| Independent end-to-end | Existing exact negative assertions exclude production, WAN, entire PQ node, quantum hardness, rollback and whole-system Hepta FinalUse qualification claims. | At-head source/lockfile evidence, independent crypto review, reproducible deployment, WAN/fault benchmarks, economic attacks and authorized activation process. |

This guard does not create permission, switch profiles, sign an artifact, accept a proof, change chainwork or modify the consensus rules. All six gates remain UNQUALIFIED. This research-only v1 guard must not be weakened to force a green release; any later upgrade requires a reviewed new security schema and independently verifiable evidence.

References: NIST FIPS 204 (ML-DSA); RISC Zero 3.0 cryptographic security model (RISC-V 96-bit, recursion 99-bit, Groth16 not quantum-safe); Bailey & Sattath (2024) quantum miner / difficulty adjustment research. Those RISC Zero component estimates do not assign a security-bit level to the current native Node. None is a proof of full Trillionnium-Chain security.


## Convergence owner coverage

The same authorization and migration gates now require the source paths for the
classical/PQ client boundary, continuous History receiver, TCD1 acquisition,
original M06 funding/payment observation, M12/M09 retirement and source-preserving
growth rehearsal. The [authority surface audit](PQ_AUTHORITY_SURFACE_AUDIT_20261031.md#pn0pn6-convergence-dependency-coverage)
records which owner supplies each effect and the remaining limitations. These are
coverage additions to the existing six gates, not a new release policy. The
[integration checker](../../scripts/ci/check_pq_research_integration.py) requires
actual blob identities and rejects omitted dependencies; this guard independently
refuses missing owner paths and unsupported promotion. Neither executes a model
loader, verifies external custody, proves a monetary effect, or closes PN6.

## Native witness and live admission continuation

The [2026-11-01 continuation](PQ_SYSTEM_CONTINUATION_20261101.md) adds explicit
source dependencies for the native witness service, its transactional PNQ2
integration, and live-admission regression controls. Missing implementation or
test modules are refused by the claim guard; their presence does not qualify
their runtime behavior. Actual positive effects, refusal, cold reopen and failure
records remain separate from the source/claim checks. All six gate states remain
UNQUALIFIED and every existing negative activation assertion is preserved.


## 2026-11-03 integrated source continuation

This continuation starts from Chain #688 `116a3caf6046dd0db3caf1d0797e636c35c877b8`
and checks Hepta #4497 `f28af9b7700a61fbbcdcc121521cb879297d5e31`. A component
result from #683 does not qualify the combined #688 source. The missing admission
guard retention and two original controls are now integrated; the required list
keeps all 43 original controls in order and adds those two. Actual execution on
this new composition must be recorded separately.

The selected backend remains `StateBackend::PqWitnessV4`. Its SHA-512 root
covers only PNQ2 resource, peer and request tables. V5 in paired evidence names
a qualification configuration, not a new whole-state witness backend. Chain
reorganization may change canonical balances and History; it must not rewind
local spent-use identities, revocation generations or effect reconciliation.
Extending the witness root requires a defined owner protocol across these two
state classes, rather than mechanically hashing additional database tables.

The isolated hardened W1 verifier fixes SDK 3.0.6, Poseidon2 and its verifier
parameter digest while retaining real cryptographic verification. It remains
outside the Node consensus backend. Fixing a profile does not provide a QROM
soundness proof or upgrade the published component estimates to PQ-128.

For every primitive or hash use, qualification must record the standard and
parameter set, security property, quantum model, cost metric and claim scope.
[NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) defines signature
algorithms; [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) defines key
establishment. NIST security categories are not whole-system bit counts.
Hash preimage, second-preimage and collision obligations must be evaluated
for each actual use and domain; an identity digest and a proof transcript
cannot inherit the same argument merely because both use a hash. The NIST
FIPS 204 page's 2026-07-31 errata note is an input to future conformance review,
not evidence that the current implementation is incorrect.

The remaining proof, quantum-work, complete migration/rollback, network
capacity and independently deployed end-to-end gates remain UNQUALIFIED.
The original witness, CPU and business budgets and all activation negatives
are unchanged.


## 2026-11-03 current authority composition readback

The follow-up reads Hepta #4497 at
[`a6d8ce20bf8f5b6991d2dc5ef7313812944db060`](https://github.com/TrillionniumFoundation/hepta-private-ci/commit/a6d8ce20bf8f5b6991d2dc5ef7313812944db060).
Its [Objective ingress](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/a6d8ce20bf8f5b6991d2dc5ef7313812944db060/codex-rs/hepta-agentd/src/objective_runtime.rs)
requires RunStart V1, decodes a 64-byte signature and persists
RunStartAuthenticationV1. The explicit PQ trust profile refuses this route;
this is an unsupported PQ product path, not demonstrated silent downgrade.
Its [HTTP automation constructor](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/a6d8ce20bf8f5b6991d2dc5ef7313812944db060/codex-rs/hepta-agentd/src/automation_effect_host.rs)
still constructs classical provider-contract and FinalUse authorities.

The shared SignedFinalUseGrant/FinalUseAuthority types also support explicit
MlDsa65V2 via
[the fresh PQ owner namespace](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/a6d8ce20bf8f5b6991d2dc5ef7313812944db060/codex-rs/hepta-contracts/src/final_use_pq.rs).
Accepting those generic types does not prove a production host is classical-only.
Every concrete host must bind its selected profile, independent issuer keys,
protected time, consumed-use identities and current external revocation frontier.
RunStart migration needs a versioned authenticated journal and restart/replay
validation; changing a signature array does not migrate its owner protocol.

The paired FinalUse frontier correction
[#4729 at 5fa90c21](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/4729)
has separate source and native qualification. Its source review cannot supply
the missing original contracts-package or composed-deployment acceptance.
Local Chain governance role strings and host-injected release-verifier contracts
are not deployed PQ trust roots. The three-table witness scope above remains
unchanged. All six original qualification gates remain open.
