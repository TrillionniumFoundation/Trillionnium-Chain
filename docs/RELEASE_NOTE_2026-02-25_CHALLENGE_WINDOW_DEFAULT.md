# Release Note — 2026-02-25

## Trillionnium Rust L1 (PoUW)

### Change
- Align runtime default `challenge_window_blocks` with governance schema minimum.
- `DEFAULT_CHALLENGE_WINDOW_BLOCKS` updated from **20** to **100**.

### Why
- Removes semantic drift between runtime defaults and governance-validated parameter bounds (`[100..600]`).
- Improves safety margin for challenge/resolve timing when governance override is absent.
- Keeps protocol semantics easier to reason about and audit.

### Scope
- Target crate: `trnm-pouw`
- No governance bound change.
- No state migration introduced.

### Validation
- `cargo test -p trnm-pouw` passed.
- Governance lower-bound behavior remains enforced in `trnm-state` (invalid value 99 still rejected).

### Operator note
- If your deployment relied on the implicit old default (20), set an explicit governance parameter intentionally.
- Recommended: keep default-aligned policy unless there is a documented rationale to deviate.
