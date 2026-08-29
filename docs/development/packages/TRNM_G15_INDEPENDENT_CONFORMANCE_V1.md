# G1.5 independent CEV1 conformance v3

Status: **BLOCKED_UPSTREAM / candidate-non-normative**

Package ID: `G15_INDEPENDENT_CONFORMANCE_V1`
Agent: `A09`
Upstream: `A08` corrected CEV1 registry candidate
`6c42673db5bc46f82934dddc678a1752a092ca04` / tree
`df8f6bf0cfe0868668f86ba9b41fc34ce1a085c4` (exact pin; candidate only)

## Scope

This package is a separately authored Python standard-library implementation
for the CEV1 registry and catalog inventory.  It does not import the A08
checker, a Rust crate, a canonical serializer, or any production protocol
implementation.  The A08 checker is run only as an independent subprocess
cross-check and its path, source hash, return code and output hashes are bound
in the evidence envelope.

The parser strictly enforces:

- one UTF-8 JSON value (duplicate keys, non-finite constants, trailing values,
  invalid UTF-8, controls and unpaired surrogates are rejected);
- exact top-level and nested key sets and exact JSON/TOML scalar types (a JSON
  boolean can never pass as an integer);
- the complete operation range `0..29`, canonical name/body type/plane/
  authority/nonce, candidate/disabled status and `enabled=false`; corrected
  disabled profile rows are enforced at kinds 20 and 27, while kind 29 is the
  candidate `EconomicObject` row (there is no stale kind-29 sentinel);
- object/catalog order and planning-plane projection, candidate wire states,
  known authority classes, and no activation;
- exact digest-domain values, error code/class/retryability mapping, positive
  bounded limit names/types, and verification-profile shape/evidence/authority
  boundaries with fallback disabled.

The operation assignment is duplicated in the A09-owned
`conformance/cev1/registry-v1/operation-mapping-v1.json` fixture.  The fixture
is checked against the in-code map and carries the exact A08 source pin,
preventing a generic shape checker from silently accepting a remapped
operation.

## Retained negative corpus

`conformance/cev1/registry-v1/negative-cases.json` retains 51 mutations covering
duplicate top-level and nested keys, trailing JSON, NaN, unknown fields,
boolean-as-integer confusion, operation mapping/status/enablement drift,
object/catalog projection drift, domain/error/limit/profile shape and mapping
drift, and operation-map fixture drift.  Each case records a target, recipe,
expected rejection class and the observed error.  Mutants are applied only to
temporary copies; the candidate checkout is never modified by the harness.

## Commands

```bash
bash scripts/ci/check_independent_cev1_registry_v1.sh
python3 tools/independent-cev1-parser/registry_conformance.py \
  --root . --skip-a08-checker --mutants-only
```

The shell gate requires the exact A08 pin, a clean source tree, the independent
subprocess checker, all 51 retained mutants, and a deterministic evidence ID.
It exits with `status=MODULE_CLOSED_CANDIDATE` after the pin is verified; the
package/PR remains candidate-non-normative and control-ledger/independent-review
promotion is still blocked.  To exercise the explicit pending branch, make a
temporary archive (never edit the candidate checkout), replace both fixture
pins there, and omit `--require-a08-pin`:

```bash
pending_root=$(mktemp -d)
git archive HEAD | tar -x -C "$pending_root"
sed -i 's/6c42673db5bc46f82934dddc678a1752a092ca04/<pending-a08-correction>/; s/df8f6bf0cfe0868668f86ba9b41fc34ce1a085c4/<pending-a08-correction>/' \
  "$pending_root/conformance/cev1/registry-v1/operation-mapping-v1.json"
python3 "$pending_root/tools/independent-cev1-parser/registry_conformance.py" \
  --root "$pending_root" --skip-a08-checker \
  --evidence-out "$pending_root/a09-pending-evidence.json"
```

The normal exact-pin replay is:

```bash
python3 tools/independent-cev1-parser/registry_conformance.py \
  --a08-source-commit 6c42673db5bc46f82934dddc678a1752a092ca04 \
  --a08-source-tree df8f6bf0cfe0868668f86ba9b41fc34ce1a085c4 \
  --require-a08-pin --evidence-out /tmp/a09-evidence.json
```

The exact candidate `HEAD`/tree and dirty-path list, raw and canonical content
hashes for all six registries, catalog, operation map, negative corpus and
plan, plus A08 subprocess hashes, are recorded in the evidence JSON.  The
top-level `evidence_id` is `g15-a09-` plus the first 32 hex characters of
SHA-256 over the documented stable canonical projection (source commit/tree,
exact upstream tuple, all input digests, negative outcomes and machine flags).
Branch names, dirty-path diagnostics and absolute checkout paths are excluded
from that projection; `evidence_id` is recomputed and a payload-mutation
negative is retained by the gate.

## Non-claims and open dependencies

```text
global_cev1_conformance_complete=false
full_cev1_binary_parser=false
normative_freeze=false
node_support=false
production_candidate=false
production_consensus_activation=false
```

The package/PR cannot be promoted beyond candidate status until the A08
semantic-correction commit/tree and operation mapping receive control-ledger
and independent review acceptance, even though the exact pin is now replayed.
Full binary object interoperability,
light-client proof, formal review and the accepted G1 exit remain open.  Any
change to a registry identifier, domain, error, limit, profile or operation
mapping invalidates downstream A10 W0-W7 rows and all consuming vectors.
