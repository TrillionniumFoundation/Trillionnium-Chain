# Trillionnium Native PoCO node decomposition v1

Status: repository implementation candidate; production activation remains false.

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
- `.github/workflows/trnm-node-decomposition-v1.yml` executes static checks,
  locked offline Cargo-tree equivalence, formatting, tests, strict Clippy, and
  real CLI status/start behavior against the exact source head.

## Non-claims and remaining work

This decomposition closes the package-boundary and production-entrypoint part
of `NODE-SPLIT-001`; it does not claim that the persistent validator is complete.
In particular, it does not supply a production network listener, pacemaker,
Vote/Timeout loop, signer/HSM, application finalization driver, state-sync
downloader, RPC/indexer runtime, multi-host evidence, power-loss evidence,
independent audit, soak, governance approval, or activation. All production,
consensus-activation, public-testnet, release, and G5 flags remain false.
