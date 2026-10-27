# PAB1: atomically visible complete PCB1 Cell bundle (RESEARCH ONLY)

Parent is Chain #455 (PCS1 signed loopback Swarm). This increment does **not** change PoN W1/PNW1, installed Ed25519, QTX1, chainwork, transaction/block limits, model adoption, Hepta authority, or activation. No mainline merge is claimed.

## Goal and exact bytes

`pq_cell_bundle_atomic.py` reads canonical `PCB1` version 1, the *exact* existing Base and 1..16 Cell entries. The caller supplies independently pinned manifest SHA-384, network, family, parent and generation; those pins are never accepted from a remote PCC1 catalog. It requires exactly one route per Base/Cell. Each PCC1 must bind the **same PCB1 manifest digest**, network, generation and object size; it checks the existing `TRNM/PoN/PQCellCustody/v1\0catalog\0` digest. Upstream `pq_cell_swarm.fetch_to_immutable_file` is the **default** fetcher: that separate module authenticates per-chunk PCR1 with real ML-DSA-65 and Merkle proofs. This increment does **not** reimplement PQ signatures.

`PAB1\x01` readiness index fields are fixed and big-endian: 5-byte magic/version, 48-byte PCB1 manifest ID, 32-byte network, 32-byte family, 32-byte parent, 8-byte generation, 1-byte object count, 16-byte random stage ID, then exactly N ordered 96-byte (selector32, generation8, content SHA-384 ID48, size8) entries. `selector=0x00*32` is the shared Base; the remaining selectors are exact sorted unique PCB1 Cell IDs. Unknown/trailing bytes and all identity changes reject.

All authenticated downloaded bytes are re-opened via `O_NOFOLLOW`, checked as regular single-link files with expected size, and streamed through the existing PCB1 content domain SHA-384 before a release becomes visible. The staging directory is private and content remains invisible to readers until `os.link` publishes exactly one immutable readiness index. This is a no-replace single-file linearization point: it does not publish partially downloaded bundles. Exact index inode/link identity, manifest and **every** object is checked again by `read_published` after cold reopen. The root directory is fsynced before staging, and the pending directory entry is fsynced **before** the readiness hardlink is created; this prevents a durable published index from referring to a non-durable stage name after a crash. Concurrent identical publishers cannot replace the first pointer; orphan stages have no visibility. Post-link fsync failure is **indeterminate** and retains the pointer/stage for reconciliation rather than pretending a rollback.

Limits: 17 objects, <=64MiB each, <=256MiB per bundle. Local root and created directories must be owner-only. Read-only data and published pointer opens are nonblocking and no-follow, rejecting FIFO attacks *before* they can hang on open; missing Linux file-open safety flags fail closed. This does not defend against privileged/same-UID malicious filesystem ancestry replacement, corrupted device firmware, full volume snapshots/rollback or physical power-loss; full native directory-fd/namespace and nonrewindable external anchor are outstanding.

## Actual tests and failure scope

`PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v test_pq_cell_bundle_atomic.py`

20 local **storage-only** tests pass on the source identity recorded in the adjacent evidence. Tests deliberately inject an **untrusted fake fetcher**, exercising wrong bytes, missing late Cell, signed-but-mismatched catalog claim, caller pin mutation, duplicate/missing selectors, 8 concurrent writers, symlink/FIFO output and FIFO readiness index, safe O_NOFOLLOW/O_NONBLOCK opens, immutable no-clobber, cold byte and index corruption, orphan stage, enforced stage-before-pointer fsync order, failed pre-link fsync and uncertain post-link fsync. These tests do **not** execute PCS1 / ML-DSA or the inherited Chain suite; PQ signature correctness is an external prerequisite already separately tested by #455.

## Mandatory blockers (OPEN / HOLD_NO_GO)

- The trusted *current* PCB1/E3 evaluation/Hepta export/withdrawal/Final-use owner remains external. Supplied pins are not self-authenticating.
- Native Rust/C++/Hepta model loader, actual chain-reorg-aware generation switch and invalidation, real release adoption authority and consistent resource/fence handling remain absent.
- No authenticated PQ WAN transport, independent P2P operators, durable storage contracts, retrieval audits, repair/erasure coding, hostile filesystem/physical power-loss qualification or sustained model availability.
- No audited native Rust ML-DSA/HSM/key rotation, full M00-M17 PQ transaction/account/fork integration or independent external cryptographic review.
- PoN W1 quantum effective-work security and hostile proof-admission cost remain unqualified. The product is **not** quantum-safe; production remains disabled.

Status is `RESEARCH_ONLY`, `independent_accepted=false`, `production_activation=false`. No user-facing capability, Chainwork, reward, FinalUse or release-authority object is returned.
