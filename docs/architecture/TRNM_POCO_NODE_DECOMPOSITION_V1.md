# Trillionnium Native PoCO node decomposition v1

Status: target decomposition contract; current candidate has unaccepted authority-boundary drift; production activation remains false.

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

## Current implementation versus target contract

The present `trnm-poco-node-authority` candidate additionally owns a
`DurableFileAuthorityJournalV0` handle and exposes `open_candidate`, `recover`,
`prepare_ingress`, `advance_to`, and durable readback. Its manifest declares
`composition_only = false` and adds direct boundary/durable-adapter dependencies.
Those facts do not satisfy the wiring-only target below or the frozen runtime
edge set. `check_node_decomposition_v1.py` must continue to reject this candidate
until the implementation is placed behind approved domain-owner contracts and
exact-source consumer/security acceptance establishes the new boundary.

Do not change `composition_only` to true, expand the allowed edge list, or mark
`NODE-SPLIT-001` closed merely to silence this failure. Journal sequencing and a
caller-provided facts digest do not independently prove consensus, execution,
signing, checkpoint, or finality authority. The host remains non-activating and
its I/O surfaces remain inert. This document records the mismatch; it does not
repair or independently accept that implementation.

## Boundary contracts

### Component library — `trnm-poco-node`

Owns the existing bounded component implementations and their exact fail-closed
production gate. Its default feature set is empty. Candidate, fixture, external
signer, lab, and process-test paths require explicit features. This package is
not the production entry point after this decomposition.

### Authority coordinator — `trnm-poco-node-authority`

May read the immutable readiness facts exported by the component library and
may delegate its static production activation gate. It exposes no sign, vote,
finalize, apply, state-root, key, storage, network, or adapter-registration API.
It owns no domain state machine.

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
requirements for `NODE-SPLIT-001`; the current authority-boundary drift means
that blocker is not closed. It does not claim that the persistent validator is complete.
In particular, it does not supply a production network listener, pacemaker,
Vote/Timeout loop, signer/HSM, application finalization driver, state-sync
downloader, RPC/indexer runtime, multi-host evidence, power-loss evidence,
independent audit, soak, governance approval, or activation. All production,
consensus-activation, public-testnet, release, and G5 flags remain false.
