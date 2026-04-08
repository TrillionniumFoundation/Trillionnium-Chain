# A2A Contract (v1, fail-closed)

## Scope
This contract defines the minimal machine-checkable behavior for A2A provenance fields emitted by `trnm-worker-agent` and consumed by downstream audit/index paths.

## Canonical field
- Field: `llm_provenance.agent_protocol`
- Canonical accepted value for A2A family: `"a2a"`

## Normalization rules (producer side)
Implemented by `normalized_agent_protocol(...)` in `crates/trnm-worker-agent/src/main.rs`:

1. Trim + lowercase input.
2. Reject non-ASCII/control/invisible filler chars.
3. Alias normalize common A2A spellings (examples):
   - `A2A v1`
   - `Agent-to-Agent`
   - `Agent 2 Agent Protocol`
   - `Google A2A JSON-RPC v2`
4. Emit canonical `"a2a"` only when recognized.
5. Unknown/invalid values => `None` (drop field, fail-closed).

## Fail-closed invariants
- No best-effort passthrough of unknown protocol labels.
- Malformed or poisoned protocol labels must not enter persisted provenance.
- Invalid adapter command spec must fail before execution.

## Minimal executable checks
- Unit tests in `trnm-worker-agent` cover:
  - accepted A2A alias normalization to `"a2a"`
  - rejection of invalid/injected labels (field dropped)
  - command-spec quote validation and shell-metacharacter prompt non-execution

## Compatibility note
This is a producer-side normalization contract for audit consistency, not a transport protocol spec.
Future versions should version this document as `a2a-contract-vN.md` and preserve backward compatibility in index/export consumers.
