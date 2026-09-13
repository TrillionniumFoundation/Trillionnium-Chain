# M15 Node Composition / Packaging / Release technical specification v1

Status: **implementation contract; no release authority**

## Authority

M15 wires reviewed implementations into processes, validates configuration,
owns lifecycle and feature/dependency closures, and produces reproducible
artifacts, SBOMs, provenance, signatures and operator handoff. Composition
contains no domain state machine and cannot weaken M02/M03, invent a root or
promote machine truth.

## Interfaces

The node constructor consumes closed-world configuration and explicit
capabilities for M01-M08 and M13. Separate build closures exist for
`node-prod-v0`, `node-devnet-v0`, `ai-v1-candidate` and
`lab-and-evidence`. Each closure has an allow-list of crates, features, binaries,
configuration schemas and external services. Candidate, fixture, benchmark,
research, PoC and legacy consensus packages are forbidden in production.

Release inputs bind source commit/tree, prospective merge, toolchain, lockfile,
features, target, container/base image, configuration schema, binary and library
digests, SBOM, provenance statement, signer identity and migration compatibility.

## State machine

```text
Constructed -> ConfigValidated -> AuthorityRecovered -> NetworkEligible
 -> Serving -> Draining -> Stopped
```

`NetworkEligible` is unreachable until Safety, signer, ledger, application,
state and checkpoint authorities agree. Shutdown drains or durably records every
intent. Upgrade follows `Staged -> Verified -> Activated`; failure returns to a
separately verified previous binary without reusing unsafe signer state.

## Persistence and recovery

M15 owns no hidden recovery database. It invokes module recovery in dependency
order and records a non-authoritative lifecycle receipt. Configuration,
artifact and authority identities are revalidated on every start. Downgrade is
rejected when schema, protocol, signer watermark or finalized state is not
compatible. Migration always targets a fresh namespace and signed descriptor.

## Resource bounds

Startup, shutdown, recovery, migration and health checks have explicit time,
memory, disk and retry ceilings. Process supervision prevents unbounded restart
loops. File descriptors, threads, worker pools, queues, log volume and temporary
artifact space are bounded by validated configuration.

## Security

Candidate-controlled code never receives repository or release-signing
credentials. Build and publication are separate trust domains. Builders are
ephemeral, read-only and tokenless; publishers execute no candidate code,
verify content-addressed inputs and use expected-head compare-and-swap. Releases
require two-person review, signed immutable manifests, SBOM/provenance and
artifact transparency. Secrets never enter build logs or deterministic cores.

## Observability and SLO

Node lifecycle uses `authority-hot-path-v1`; build/release uses
`evidence-tooling-v1`. Metrics include startup/recovery time, authority mismatch,
restart count, shutdown drain, binary/config identity, dependency closure,
reproducibility result and artifact verification. A health endpoint cannot
override a fail-stop authority state.

## Verification and evidence

Qualification includes dependency/feature closure scans, clean and offline
builds, two independent reproducible builds, artifact tamper tests, clean
install, startup/shutdown/crash, upgrade/downgrade refusal, migration rehearsal,
configuration mutants and release-signature verification. The prospective merge
and post-merge artifact are replayed, not inferred from a topic-branch binary.

## Activation boundary

No release is accepted while the PR is draft, required lanes are empty,
skipped, queued or `action_required`, independent reviews are missing, or
external HSM/power-loss/audit/soak gates are open. Administrator permissions do
not substitute for the evidence contract.
