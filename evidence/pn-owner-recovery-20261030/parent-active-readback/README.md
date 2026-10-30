# Parent and active readback: bounded native component evidence

This continues the original transaction-local readback on adopted parent
`a38d770966c65ad34c9d5e55f3c2917c2e3bda0f`. It does not grant production,
whole-chain post-quantum, full PN2, public throughput or independent-host
qualification. The actual subsequent published source and merge must have their
own execution records.

The [manifest](manifest.json) binds every retained small archive member and the
[original evidence archive](parent-active-readback.tar.gz). Large native
executables are identified by their original and compressed hashes in the
retained receipts; their bytes are kept in the separate complete evidence bundle.
This Git archive excludes those executable bytes and includes the original logs,
patches, source manifests, layout witness, cost data and review records.

## Fix and trust boundary

The existing owner may retain four named graph results within its same original
CanonicalJson write transaction: child, genesis, verified child parent, and the
active tip obtained by the original reader. The parent's identity comes only
from a successfully verified child Record. Active nomination uses the existing
tip read. Neither operation performs earlier discovery SQL, mints a proof,
replaces a nominated role, or renews an invalidated transaction scope.

Every reuse still checks the current full State commitment and original
Record/block/parent/delta data. The original SQLite connection, transaction,
write epoch and schema fence remain required. Any subsequent mutation invalidates
the scope. If a result has already been consumed, the enclosing operation must
refuse; disabling only future hits would be insufficient.

The active reader now checks that consumed scope after its final callback and
tip/generation/slot comparison, before publishing the active commitment view.
Final admission retains its check after the last callbacks and before the
existing effect-marker write. The original shared-storage and no-receipt
paths remain unchanged. A fifth unrelated root is not retained.

## Actual results

| Selection | Passed | Failed | Ignored | Scope |
| --- | ---: | ---: | ---: | --- |
| Qualified native RED, three new controls | 1 | 2 | 0 | Original parent reuse and final active callback regressions |
| Qualified native GREEN, same three controls | 3 | 0 | 0 | The new tests only |
| Complete authenticated module, original test profile | 76 | 0 | 1 | Release-only retained-delta cost control remains ignored here |
| Complete authenticated module, original release profile | 77 | 0 | 0 | Includes the actual retained-delta cost control |
| Original owner/snapshot selection | 22 | 0 | 0 | Existing selected native owner controls |
| Combined-source PQ owner selection | 14 | 0 | 0 | Existing selected native PQ controls |

These are overlapping selections, not additive whole-project coverage. The
release selection filtered 827 unrelated library tests; its 7.23-second test
runtime is not a transactions-per-second claim. The original test profile uses
the workspace's node optimization setting and retains debug assertions. It is
not substituted for `--release --include-ignored`.

The release command creates a new `TRNM_RETAINED_DELTA_COST_PATH`. The unchanged
`retained_delta_stream_cost_preserves_all_paired_observations` control actually
runs and passes. Its JSONL observations and receipt remain in the archive.
The 32 observations form 16 paired original delta-stream controls. They verify
equal results and retained observations without a speed threshold; their
in-memory SQLite timings do not measure the new parent/active reuse, full Node
State/History work, physical I/O, RSS or TPS.
Package-scoped Clippy with `--all-targets --all-features -- -D warnings` passes.
Formatting and generated source-inventory checks preserve the reviewed source.

The qualified RED fails because the parent graph is traversed five times rather
than four and because the final active callback can otherwise return stale
success after a controlled KV write. The corrected source passes those exact
controls without weakening their assertions.

## Preserve failures and source identity

The earlier exploratory native run used an unqualified layout and also exposed
an incorrect cold-reopen test assumption. That assumption was corrected before
the qualified RED: ordinary recovery can select the heavier admitted child.
The original exploratory log and fixture bytes remain retained, without being
presented as the definitive qualified RED.

A subsequent canonical compilation was interrupted by SIGKILL before tests.
That is infrastructure failure, not a test pass or a vulnerability demonstration.
The guarded dependency's derived build products were cleaned once before the
successful canonical build; no layout guard or budget was changed.

Both fresh canonical debug and release observations retain the unchanged
`sqlite-3.51.3-normal-native-linux-layout-v3` fence and the original SQLite
amalgamation hash. This does not prove physical power-loss recovery, storage
durability on arbitrary hosts, or independent bit-for-bit build reproduction.

The original four reviewed Rust files are recorded separately from the generated
inventory update. The official inventory generator adds exactly the new test
file entry, seven lines. Its addition occurs after the library release run and
before the final all-targets/all-features Clippy; it changes the examples' source
inventory and does not retrospectively change the earlier library test inputs.

`functional-evidence.json` retains its original earlier pending release/lint
snapshot. Later completion is recorded separately. Older records are not
rewritten to claim they already contained later results. The retained complete
five-path patch reconstructs the final code and generated inventory on the
adopted parent; later workflow, plan and evidence files are a separate change.

## Remaining acceptance

This is a constant-factor reuse of already verified graphs. Full State work and
tip-to-genesis History dependencies remain. The prior exact-source hosted Raw
History and original business campaign failures remain failures; reading older
successful artifacts does not replace a new native campaign.

The original business deadlines, attack envelope, long-history/growing-account
cases, cold synchronization, deep reorganization, disk faults, independent
readback and full cross-architecture source/merge gates remain required. No
runtime profile, consensus rule, schema, resource budget or qualification flag
is relaxed by this continuation.
