# DED43A external gate execution packet v1

Status: execution handoff only; **not accepted evidence**.

## Exact subject

- Repository: `TrillionniumFoundation/Trillionnium-Chain`
- Candidate PR: `#101`
- Source commit: `ded43a0704b455cd4bef724cb3ca40fb6db9465d`
- Source tree: `c0791ffb57e05fde43f87bfed1a3b4656c09efc0`
- Parent policy PR: `#100` at `b3a628744e23fb93ef510ab38a748a2ff7416651`
- Prospective merge object: `6a46d99fcdf916a3f36a7261665e9ce05badbc34`
- Active plan: `docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`
- Plan digest declared by `docs/development/plan-manifest-v1.toml`: `3190c7d9b485f687a421d84764911cb1d5f18483731b707fb8775a5247768504`
- Compiler: Rust `1.95.0`
- Lock input: `trillionnium/Cargo.lock`

Any source, tree, prospective merge, plan, compiler, lockfile, protocol registry, feature closure, topology, hardware, custody, or policy change invalidates downstream acceptance.

## Required independent lanes

### EXT-REVIEW-001

A non-author reviewer must independently clone the exact commit, recompute the source tree and all declared digests, replay valid protocol vectors and every retained P0 mutant, inspect the CodeQL settings verifier and the five Rust log redactions, and record every finding with source location and severity. Producer and accepting reviewer must be distinct identities and control domains.

### EXT-G1-CAMPAIGN-001

Run authenticated 4/7/31/100-process campaigns across independently operated physical hosts and custody domains. Retain topology, host identity, process identity, network fault schedule, signed runtime events, restart/rejoin/state-sync traces, finality/readback roots, resource measurements, raw logs, wall-clock timestamps, and immutable artifact hashes.

### EXT-ANCHOR-HSM-001

Use device-backed non-exportable validator keys and an independently administered monotonic anchor. Demonstrate provisioning, authorization, persist-before-sign, rollback rejection, clone rejection, rotation, revocation, quorum recovery, and destruction/retirement. Retain device attestations and signed audit trails.

### EXT-POWERLOSS-001

Execute destructive physical power interruption and controller-cache-loss cases on independent hardware. Retain exact cut points, storage/cache configuration, pre-cut roots, restart logs, journal/checkpoint reconstruction, post-recovery roots, non-mutation on invalid recovery, and independent witness signatures.

### EXT-AUDIT-001

Commission independent consensus, cryptography, economic-security and red-team reviews against this exact tuple. Every Critical or High finding must be fixed and replayed on a new exact tuple; an open Critical/High result blocks acceptance.

### EXT-SOAK-ACTIVATION-001

Only after every prerequisite is accepted, run real 72-hour chaos, 7-day public-testnet and 30-day production-candidate wall-clock campaigns. Retain incident/DR/key-rotation drills, operational SLOs, full artifact digests and the final signed governance/activation record.

## Submission contract

For every lane, create a `trnm-external-evidence-v1` submission under `docs/evidence/external/submissions/` only after the run exists. The submission must bind:

1. exact source commit/tree and prospective merge commit/tree;
2. plan, protocol/schema registry, interface, compiler, dependency and artifact digests;
3. producer, operator, reviewer, witness and custody identities and independence domains;
4. UTC start/end timestamps and real wall-clock duration;
5. complete raw artifact inventory with byte lengths and SHA-256 hashes;
6. positive and negative replay counts, retained mutants, fault schedule and outcomes;
7. findings, dispositions, residual risk and downstream invalidation set;
8. producer and independent reviewer signatures over one canonical evidence digest.

Replay with:

```bash
python3 scripts/ci/authenticate_external_evidence_v1.py --help
python3 scripts/ci/check_external_evidence_v1.py --help
python3 scripts/ci/check_external_evidence_v1.py --require-all
```

Fixtures, simulations, shortened clocks, repository self-attestation, mutable URLs, unsigned notes, workflow success alone, local watermarks, SIGKILL-only tests, or evidence for another source do not close any lane.

## Current authority boundary

```text
EXT-REVIEW-001=open
EXT-G1-CAMPAIGN-001=open
EXT-ANCHOR-HSM-001=open
EXT-POWERLOSS-001=open
EXT-AUDIT-001=open
EXT-SOAK-ACTIVATION-001=open
all_gaps_closed=false
public_testnet_ready=false
production_candidate=false
production_consensus_activation=false
release_ready=false
```
