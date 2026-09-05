# Trillionnium Native PoCO node decomposition v1

Status: candidate ownership repair; independent acceptance pending; production activation remains false.

## Purpose

This decomposition removes the production-shaped entry point from the historical
`trnm-poco-node` composition hotspot. The old crate remains the default-feature
component library and bounded candidate/test host. The production build closure
now starts at a dedicated CLI package and reaches the component library only
through four explicit, acyclic boundaries:

```text
trnm-poco-node-cli
  -> trnm-poco-node-host
       -> trnm-poco-node-authority
            -> trnm-poco-node
       -> trnm-poco-node-io
```

`trnm-poco-lab-validator` remains a separate lab runtime and is forbidden from
the `node-prod-v0` closure. AI-v1 candidate crates remain optional dependencies
of `trnm-poco-node` and are reachable only through the explicitly named
`ai-v1-candidate` feature.

## Versioned candidate ownership seam

Primary module: M15. Producer: M03 file-adapter owner. Consumers: M15 authority,
host and CLI. This is a contract change requiring producer/consumer review, not
an independent acceptance record or a replacement development plan.

The default authority package owns no journal, root path, recovery flag, receipt
validation, or transition logic. It reads immutable component readiness facts
and delegates the static activation gate. The default host has no persistent
constructor or ingress/stage-mutation API. The CLI has no candidate feature.

An explicit `persistent-authority-candidate` feature on the host forwards to the
same feature on the authority facade. Only that facade feature selects the
optional `trnm-durable-file-adapters-v0` dependency. Domain state, root checks,
recovery barriers, successor checks and receipt validation belong to
`CandidateAuthorityJournalV0` in that adapter crate. The facade only holds and
delegates to this owner; it neither caches recovery state nor validates facts.
Read-only stage/binding DTOs continue to come from `trnm-node-boundary-v0`.
The underlying `FileAuthorityCoordinatorV0` also validates identity before any
namespace creation and validates bindings before append and during recovery.
A self-consistent record hash cannot authorize a zero-height or otherwise
invalid operation binding. Rejected direct calls must leave journal bytes and
the last receipt unchanged.

`open_candidate(root, identity)` requires a valid identity and an existing
absolute non-symlink directory. No mutation is allowed before successful local
journal recovery. Recovery first closes the barrier, including when an error
prevents completion. Any failed durable append or substituted post-append
receipt also closes the barrier; deterministic preflight rejections append
nothing. Exact retries preserve their original receipt. Conflicting bindings,
zero fact digests, skipped stages and receipt substitution are refused.

The candidate digest API records caller-supplied inert facts. It does **not**
prove application, SafetyRules, signature, finality or checkpoint authority and
cannot activate production. Existing candidate tests are retained at the owner
and consumer seams. Their results must be recorded separately from default
CLI/build-closure checks; Cargo feature unification in a workspace test is not
proof of the default production closure.

The static and Cargo-resolved `node-prod-v0` closure must exclude the candidate
file-adapter package. A separate feature-enabled consumer build must retain it.
These are complementary positive/negative controls, not a new release closure.
Do not mark `NODE-SPLIT-001` accepted until unchanged-source tests and independent
producer, consumer and security review accept this repair. No dependency allowlist
is widened and no production or external-evidence flag is promoted.

## Boundary contracts

### Component library — `trnm-poco-node`

Owns the existing bounded component implementations and their exact fail-closed
production gate. Its default feature set is empty. Candidate, fixture, external
signer, lab, and process-test paths require explicit features. This package is
not the production entry point after this decomposition.

### Authority coordinator — `trnm-poco-node-authority`

May read the immutable readiness facts exported by the component library and
may delegate its static production activation gate. Its default build exposes
no sign, vote, finalize, apply, state-root, key, storage, network or
adapter-registration API. The explicit candidate seam delegates journal calls
to the domain owner described above. Neither build owns a domain state machine.

### I/O runtime boundary — `trnm-poco-node-io`

Names the I/O surfaces needed by a complete validator but constructs none of
them. Every surface is inert: authenticated P2P, pacemaker timer, state sync,
RPC, indexer, and telemetry. There is no public enabled-surface constructor and
no callback into consensus authority.

### Host composition — `trnm-poco-node-host`

Performs wiring only. It joins the authority readiness boundary to the inert I/O
boundary and produces a sanitized status. `start()` remains fail-closed unless
the component library's exact activation gate is open, all readiness facts are
accepted, and every required I/O surface is active. This revision provides no
activation mechanism, so start cannot succeed.

### CLI entry point — `trnm-poco-node-cli`

Depends only on the host composition package. `status` emits bounded sanitized
machine-readable readiness. `start` always delegates to the fail-closed host
boundary and exits non-zero. It cannot directly import the component library or
any consensus, storage, signing, networking, or finality crate.

### Lab boundary — `trnm-poco-lab-validator`

Remains outside the production closure. Lab fixtures, raw keys, synthetic
validators, and development networking do not enter `node-prod-v0`.

## Machine enforcement

- `config/node-decomposition-v1.toml` freezes package roles and runtime edges.
- `scripts/ci/check_node_decomposition_v1.py` compares those edges with Cargo
  manifests, checks acyclicity and fail-closed metadata, rejects direct CLI to
  kernel dependencies, rejects authority methods and live I/O backends, and
  binds the production closure root to the dedicated CLI.
- `config/build-closures-v1.toml` recursively resolves production, devnet,
  AI-v1 candidate, and lab/evidence closures.
- `.github/workflows/trnm-required-baseline.yml` is the actor-independent
  execution owner for static decomposition checks, Cargo-tree equivalence,
  formatting, all-target workspace and package tests, strict boundary Clippy,
  and real CLI status/start behavior against the exact source head. The
  duplicate unregistered decomposition workflow is retired; no underlying
  assertion or protected required check is removed. Privileged focused tests
  retain their separately frozen X230 identity and offline-cache policy.

## Non-claims and remaining work

This decomposition defines the package-boundary and production-entrypoint
requirements for `NODE-SPLIT-001`; independent acceptance is still required
before that blocker closes. It does not claim that the persistent validator is complete.
In particular, it does not supply a production network listener, pacemaker,
Vote/Timeout loop, signer/HSM, application finalization driver, state-sync
downloader, RPC/indexer runtime, multi-host evidence, power-loss evidence,
independent audit, soak, governance approval, or activation. All production,
consensus-activation, public-testnet, release, and G5 flags remain false.
