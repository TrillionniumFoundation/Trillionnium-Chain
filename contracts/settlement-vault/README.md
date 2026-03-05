# SettlementVault (MVP Skeleton)

This directory hosts the **external SettlementVault MVP skeleton** for M0 lane work.

## Files

- `src/SettlementVault.sol`: MVP interface + state machine skeleton
- `test/SettlementVault.t.sol`: placeholder test plan stub

## Scope

- Not wired to main execution path
- Spec-first, audit-friendly shape
- Minimal-risk controls: pause, role checks, requestId anti-replay, explicit events

## Suggested toolchain (Foundry)

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

Then run:

```bash
cd contracts/settlement-vault
forge test -vv
```

> Note: repo-level `foundry.toml` and OZ dependency wiring are not yet integrated in this lane commit.
