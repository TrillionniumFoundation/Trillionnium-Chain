# G1.5 independent CEV1 registry conformance v1

Status: **MODULE_CLOSED_CANDIDATE for registry conformance / global CEV1 conformance remains open**

Package ID: `G15_INDEPENDENT_CONFORMANCE_V1`
Agent: `A09`
Upstream registry commit: `c6749f9e959a0838b200190c730fc28e053bbec7`

This package adds a separately authored standard-library implementation for the A08 registry surface. It imports no TRNM Rust crate, canonical serializer, or existing protocol checker.

## Covered

- duplicate-key-rejecting JSON parser;
- deterministic canonical JSON bytes and SHA-256 evidence roots;
- independent operation/object/domain/error/limit/profile semantic checks;
- retained in-memory mutants for missing slots, duplicate keys, enabled operation, enabled profile, fallback, duplicate domain, malformed domain, and nonpositive limits;
- machine-readable evidence summary.

## Explicitly excluded

This is not a second implementation of every CEV1 binary object. Existing listed-type independent checkers remain separate evidence, and complete global CEV1 wire/parser/light-client conformance is still open.

## Command

```bash
bash scripts/ci/check_independent_cev1_registry_v1.sh
```

## Stop conditions

A registry semantic mismatch, unexpected successful mutant, duplicate key, changed canonical digest without a new evidence epoch, or an enabled operation/profile is a fail-closed result.

## Non-claims

```text
full_cev1_parser_complete=false
normative_freeze=false
wire_schemas_complete=false
interoperability_complete=false
node_support=false
production_candidate=false
```
