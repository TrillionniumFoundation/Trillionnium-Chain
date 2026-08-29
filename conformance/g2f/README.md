# G2F whole-node / light-client conformance (candidate)

This directory is an executable, stdlib-only candidate slice for
`G2F_WHOLE_NODE_LIGHT_CLIENT_V1`.  It is deliberately outside the canonical
Rust crates and does **not** grant signing, voting, activation, production, or
release authority.  A green run is local candidate evidence only.

## What is covered

* `wire.py` and `fixture.py` define one bounded binary `TRNM-G2F1` carrier.
  The carrier binds the context, finalized height/header, application sparse
  (JMT-shaped) root, six W3--W7 proof-family payloads, and all eight W0--W7
  trace steps.
* `client_a.py` and `client_b.py` are independently authored parsers.  They
  do not import each other, the fixture encoder, or a canonical Rust parser.
  Differential tests require the same result from both clients and reject
  malformed, reordered, truncated, root-substituted, and proof-family-mutated
  carriers.
* `state_sync.py` verifies a bounded manifest and identity-compressed chunks,
  checks sorted/gap-free state keys and recomputes the application root, then
  models an isolated staged swap guarded by a separate monotonic anchor.
  Namespace-copy/rename, stale-anchor, torn, sidecar/WAL, interrupted-intent,
  and full-store rollback mutants are fenced before the model can reopen.
* `atomicity.py` authenticates a common transaction/version cut across the six
  named planes and provides strict double-sampling/ABA rejection. It is an
  executable boundary proposal, not a database transaction implementation.

The state-sync and carrier domains are candidate domains.  They are not a
claim that the corresponding canonical Protocol 09 interfaces have been
accepted; missing upstream contracts remain interface-change requests owned by
the relevant A11--A15 package.

## Reproduce

From the repository root (Python 3.10+):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest conformance.g2f.test_clients_b
```

The module also emits machine-readable candidate evidence when invoked as a
script:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B conformance/g2f/test_clients_b.py
```

Run the complete local package suite and deterministic replay campaign with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s conformance/g2f -p 'test_*.py'
PYTHONDONTWRITEBYTECODE=1 ./scripts/g2f/check_g2f_conformance.sh
```

The runner refreshes and checks the exact candidate base ref, records the
bundle digest, both-client differential results, manifest-mutant campaign and
staged-swap fault fences in `docs/evidence/g2f/G2F_CONFORMANCE_RUN_V1.json`.
It is intentionally candidate-only and must be rerun after any source,
upstream-interface or canonical-input change.

The result includes the client pair, W0--W7 stages, W3--W7 family list, test
counts, and explicit non-claims.  Any failed mutant is retained as a failed
test; it must not be converted into a production or private-alpha claim.
