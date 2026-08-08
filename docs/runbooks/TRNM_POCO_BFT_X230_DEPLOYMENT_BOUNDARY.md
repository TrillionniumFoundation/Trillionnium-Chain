# TRNM PoCO-BFT X230 Deployment Boundary

Status: binding for PoCO-BFT v0 development and validation
Last verified: 2026-08-04

## Purpose

This runbook separates development from deployment so PoCO-BFT services and
state never contaminate the local development host.

The terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative.

## Binding execution boundary

1. The local host is for source editing, review, deterministic tests,
   simulators, formal-model checks, and Cargo builds only.
2. The local host MUST NOT run validator, full-node, signer, seed, RPC,
   monitoring, fault-injection, or soak-test services. It MUST NOT hold live
   chain databases, WALs, signing journals, or validator private keys.
3. All service deployment and all LAN, public-network, fault, recovery, and
   soak validation MUST be performed through the X230 deployment/control host
   using ordinary OpenSSH via the configured alias `p4-x230`.
4. `p4-x230` is the canonical automation target. The literal alias `x230` is
   not currently configured and MUST NOT be assumed to work.
5. Tailscale supplies the private network path, but Tailscale SSH is not the
   selected login mechanism. Automation MUST use ordinary `ssh p4-x230` with
   non-interactive failure behavior, for example `BatchMode=yes` and a bounded
   connection timeout.
6. A public or multi-region test MAY contain machines other than the X230, but
   its deployment control, operator actions, and evidence collection MUST run
   from or through the X230. The local development host remains service-free.
7. Repository remote CI MUST run on the dedicated X230 GitHub Actions runner
   selected by `self-hosted`, `Linux`, `X64`, `x230`, and
   `trillionnium-chain`. GitHub-hosted or other paid runners are not
   authorized. The runner MUST use a dedicated unprivileged service identity
   with no `sudo`, Docker group, SSH login material, deployment credentials, or
   access to `/srv/trillionnium-chain` and operator-private homes. Its checkout
   and tool caches MUST remain under that dedicated identity's home directory
   and MUST NOT be treated as deployable release provenance. Workflows MUST
   fail closed on missing preprovisioned operating-system tools rather than
   install packages with host privileges. Every self-hosted job MUST also bind
   the canonical private repository, the trusted initiating and triggering
   actor, and same-repository pull-request provenance before runner allocation;
   scheduled default-branch jobs are the only actor exception.
8. The single runner executes one job at a time. Job timeouts MUST cover an
   X230 cold cache (including pinned toolchain acquisition and clean-checkout
   Rust compilation) rather than inherit GitHub-hosted runner timings. Longer
   bounded timeouts do not relax any test assertion; first-run wall times are
   reviewed before later tightening.

No deployment is authorized merely by this document. Starting, stopping, or
replacing a service remains an explicit deployment action.

## Artifact flow and integrity

Deployment does not depend on a mutable source checkout or compiler under
`/srv/trillionnium-chain`. The separately isolated CI runner may check out
source and install pinned user-scoped test toolchains under its dedicated home.
Release artifacts promoted into the deployment root MUST still be immutable
inputs with the provenance and integrity records below.

Each transfer MUST follow this sequence:

1. Build a locked release binary or an OCI/container archive locally for the
   remote Linux `x86_64` target.
2. Record the source commit, build profile, toolchain version, enabled
   features, artifact filenames, and configuration-schema version in a release
   manifest.
3. Generate SHA-256 checksums for the manifest and every binary, archive, and
   migration payload before transfer.
4. Transfer the release into a release-specific `incoming/` directory on the
   X230. Source trees, Cargo caches, target directories, local databases, and
   secrets MUST NOT be transferred.
5. Recompute and compare all checksums on the X230 before unpacking, loading,
   or activating an artifact. Any mismatch MUST abort deployment and be kept
   as evidence.
6. Promote only a completely verified release. Releases MUST be immutable
   after promotion; a correction receives a new release ID.

An artifact signature SHOULD accompany the checksum manifest before public or
long-running validation. Checksums detect corruption; signatures establish
artifact provenance.

## Canonical remote layout

The deployment root is reserved as `/srv/trillionnium-chain`. It does not
exist yet and MUST be created only during an explicitly authorized deployment.

```text
/srv/trillionnium-chain/
├── incoming/<release-id>/       # transferred, not yet trusted
├── releases/<release-id>/
│   ├── bin/                     # release binaries, if using native services
│   ├── images/                  # checked container archives, if applicable
│   ├── manifest/                # build manifest, checksums, signatures
│   └── config/                  # versioned non-secret config templates
├── current -> releases/<release-id>
├── nodes/<node-id>/
│   ├── config/                  # rendered non-secret node configuration
│   ├── data/                    # chain state; never shared between nodes
│   ├── wal/                     # consensus WAL and signing journal
│   ├── logs/
│   └── snapshots/
├── evidence/<run-id>/           # immutable validation evidence bundle
└── rollback/<release-id>/       # rollback manifest and operator record
```

The `current` link selects the active immutable release. Data, WALs, journals,
snapshots, logs, and evidence MUST remain outside release directories so a
binary rollback cannot silently replace or erase consensus state.

Container volumes MUST map to the same per-node state boundaries. Container
images MUST be loaded from the verified archive; the X230 MUST NOT build them
from source.

## Keys and signer separation

- Validator, node-identity, P2P, TLS, and operator credentials MUST be distinct
  by purpose. Validator keys MUST also be distinct by node and environment.
- Private keys MUST NOT appear in Git, release archives, checksum manifests,
  logs, evidence bundles, shell history, or the deployment root above.
- When an in-process signer is temporarily required for an isolated test, its
  key directory MUST live outside `/srv/trillionnium-chain`, be readable only
  by that node's dedicated service identity, and be backed up through a
  separately authorized secret-handling procedure.
- Remote signing is the production-oriented boundary. The node receives only
  the signer endpoint, authentication material, and public identity; the
  validator private key remains in the signer boundary.
- A signing journal/WAL is safety-critical state, not disposable cache. It
  MUST be persisted, isolated per validator, backed up consistently, and never
  reset or copied to another live validator as a shortcut.
- Development, LAN, public test, and any later production keys MUST NOT be
  reused across environments.

## Preflight gate

Before any deployment or validation run, record and pass all applicable gates:

- `ssh p4-x230` succeeds non-interactively and reaches the expected hostname
  and operator account.
- The release target architecture and required kernel/libc features match the
  X230 or the intended downstream node.
- The artifact manifest and every checksum verify on the X230 before use.
- Available disk, memory, swap, file descriptors, clocks/time synchronization,
  ports, firewall policy, and Tailscale/LAN/public routes meet the run plan.
- Docker or systemd access is available for the chosen packaging method; no
  compiler, Cargo registry, or source checkout is assumed remotely.
- Node IDs, network/chain ID, genesis hash, validator set, epoch, wire-version,
  data paths, ports, and public keys are reviewed before start.
- Key ownership and permissions are checked without printing private material.
- Existing data and signing state are either absent for a fresh run or backed
  up and version-compatible. Database downgrade MUST NOT be assumed safe.
- The run has explicit success criteria, fault schedule, abort thresholds,
  rollback target, observation window, and evidence destination.
- Public validation additionally has authorized endpoints, rate limits,
  monitoring, log retention, resource ceilings, and an incident/kill path.

## Rollback boundary

Every activation MUST retain at least the immediately previous verified
release and its manifest. Rollback changes the selected immutable release; it
MUST NOT delete or rewind data, WALs, signing journals, keys, or evidence.

Before activation, capture a checksum-identified snapshot or backup appropriate
to the storage engine and document the compatible recovery point. If the new
binary changes the database, wire, epoch, or signing-journal format, the run
MUST define a tested forward-recovery or restore procedure; pointing an older
binary at newer state is forbidden unless compatibility was demonstrated.

Rollback or abort is required when integrity verification fails, the process
cannot recover deterministically, safety evidence appears, resource limits are
persistently exceeded, or the agreed availability/finality threshold is
missed. The operator record MUST state who/what triggered rollback, timestamps,
release IDs, state/snapshot identifiers, and the post-rollback health result.

## Evidence requirements

Each LAN, public, fault, recovery, or soak run MUST produce an evidence bundle
under `evidence/<run-id>/` containing, as applicable:

- source commit, release ID, build manifest, checksums, and signatures;
- redacted rendered configuration hashes, chain/genesis hash, node public IDs,
  validator-set/weight snapshot, epoch, and protocol/wire versions;
- host and service versions, start/stop times, topology, and resource limits;
- exact test/fault schedule, partition and heal timestamps, crash/restart
  events, and expected invariants;
- structured logs, metrics, finalized-height/QC observations, WAL recovery
  outcomes, resource graphs, and alert/abort events;
- final verdict, invariant violations or their absence, known gaps, rollback
  activity, and evidence checksums.

Evidence MUST be sufficient for an independent reviewer to reproduce the run
without containing passwords, tokens, private keys, unredacted environment
files, or other credentials.

## Verified X230 baseline

The following was verified read-only on 2026-08-04 through ordinary SSH using
`p4-x230`; no host IP or credential is recorded here:

- Hostname `qian-ThinkPad-X230`, operator account `qian`.
- Ubuntu 24.04.4 LTS, Linux 6.8, `x86_64`; systemd 255 is running.
- Intel Core i5-3230M with 4 logical CPUs.
- 7.5 GiB RAM, approximately 5.9 GiB available at inspection time, plus
  2.0 GiB unused swap.
- Root filesystem: ext4, 219 GiB total and approximately 189 GiB available at
  inspection time.
- Git 2.43.0 is installed.
- Docker 29.1.3 is installed; its daemon is reachable, uses `overlayfs`, and
  the operator account has Docker-group access.
- Rust and Cargo are not installed. This is expected under the deployment
  boundary and is not a blocker for prebuilt binaries or container archives.
- The Tailscale peer is online, while ordinary OpenSSH is the verified login
  path. Tailscale SSH was not advertised as a target capability.
- No Trillionnium Chain checkout or canonical deployment root exists yet.
- No matching TRNM/Trillionnium Docker container or systemd service exists
  yet. The X230 is a clean deployment target, not an already deployed node.

These resource figures are a baseline, not permanent capacity guarantees.
Preflight MUST measure them again before every multi-node or soak run.
