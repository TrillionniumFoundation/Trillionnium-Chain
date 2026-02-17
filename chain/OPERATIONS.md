# Operations / Testing Guide

## Fixture Verification
To verify cross-version semantic consistency between `lifecycle_summary_v2_ok.json` and `v3_ok.json`:

```bash
cd chain/tools/fixture_check
go run check_fixtures.go
```

This ensures that while the JSON structure evolves (v2 -> v3), the core business metrics (start/end height, status, worker address) remain identical for the same test scenario.

## Keeper Boundary Testing
We have added boundary tests for `SlashWorker` in `x/workload/keeper/msg_server_slash_worker_boundary_test.go`.

Run them with:
```bash
cd chain
go test ./x/workload/keeper -run TestSlashWorker_Boundary -v
```

Cases covered:
- **Exact Minimum Remaining Stake**: Verifies that slashing resulting in exactly 1000 stake is allowed.
- **Just Below Minimum Stake**: Verifies behavior around the 1000 stake threshold.
- **Multiple Slashes**: Ensures sequential slashes work correctly until minimum is hit.
- **Tiny Slash (Zero Amount)**: Ensures attempts to slash amounts that round down to 0 are rejected.
