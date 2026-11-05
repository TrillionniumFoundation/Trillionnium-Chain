# Explicit Hepta recovery handoff v4

**Result: the Python handoff now supplies the two recovery inputs required by the
current ordinary Hepta CLI. Full ordinary Hepta installation, recovery and
installed-next-task qualification remain HOLD.** This record covers a bounded
interoperability fix and actual Python controls; it does not create a model,
signed frontier, signer trust, product qualification or FinalUse receipt.

## Exact compatibility target and defect

The target is Hepta PR #4812 head
`1556a4df6e279055fd8196f81a4ca2fe0f19384a`, ref
`fix/hepta-ordinary-pq-effects-20261104`, observed with `updated_at`
`2026-11-05T10:57:45Z`. The inspected sources were fetched at that exact SHA:

| Source | Git blob SHA-1 |
| --- | --- |
| [Original ordinary CLI](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/1556a4df6e279055fd8196f81a4ca2fe0f19384a/codex-rs/hepta-infer-worker-host/src/bin/hepta-neural-agentd.rs) | `fd879087bad8b6245d3d7ef4a6812bb04ee00c2f` |
| [Original evidence recovery owner](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/1556a4df6e279055fd8196f81a4ca2fe0f19384a/codex-rs/hepta-agentd/src/evidence_frontier.rs) | `e17b055dc942cf2582911f03cec59695640e9950` |

That CLI requires both `--evidence-recovery-frontier-file` and
`--evidence-recovery-frontier-trust-file` before calling the original evidence
recovery preflight and preparing a model. The previous Chain handoff supplied
only host format, host config and host-config SHA-256. It therefore could not
enter this exact CLI successfully even with all native and model prerequisites.
The older `d7c32f38` reference from a retained pair is not this compatibility
target and must not inherit this observation.

## Change and authority boundary

The existing handoff owner now supports the fresh explicit schema
`pon-smollm-cell-host-handoff-v4`. It retains all v3 fields and requires
`execution_profile: protected-installed-elf-v1` plus:

```json
{
  "evidence_recovery": {
    "profile": "hepta-pq-evidence-recovery-files-v1",
    "frontier": {
      "path": "/outside-agent-roots/owner-frontier.json",
      "sha256": "<independently supplied 64-hex digest>"
    },
    "signer_trust": {
      "path": "/outside-agent-roots/owner-trust.json",
      "sha256": "<independently supplied 64-hex digest>"
    }
  }
}
```

This is a schema fragment with placeholders, not an executable configuration or
an authentic frontier. Both original files are checked against their independent
pins during load and again immediately before exec. They must be protected,
regular, bounded, canonical and unaliased, with the original native limits of
64 KiB for the frontier and 8 KiB for signer trust. Their paths must be outside
Agent home, run, workspace and fleet roots. The handoff preserves those external
paths instead of copying the files into a rollback domain. No output directory,
grant, issuer, signature or owner state is manufactured.

The original Rust owner still authenticates the PQ signatures, database lineage
and generation floor. Python file hashes confer no recovery authority. The two
pre-exec hash checks also do not make a file immutable across the subsequent
native open; the daemon independently reads and authenticates it. Excluding the
Agent paths does not establish independent physical custody or protect against
whole-host rollback.

Schemas v2 and v3 retain their prior semantics and argv. They do not silently
acquire recovery arguments or become compatible with this newer CLI. Schema v4
rejects missing inputs, unknown recovery profiles and a sealed-executable
selection; it has no fallback to the older schemas or to unqualified recovery.

## Actual observations, with skips retained

| Control suite | Observed result | Seconds | Retained output |
| --- | --- | ---: | --- |
| Installed-host suite after the change | 15 total: 8 passed, 7 skipped | 0.102 | [Complete final log](logs/installed-host-v4-final.log.json) |
| Existing host-handoff regression | 14 total: 4 passed, 10 skipped | 0.672 | [Regression log](logs/host-handoff-regression.log.json) |
| Merged runtime trial ledger, recorded-command replay | 24 passed | 2.307 | [Ledger log](logs/trial-ledger-command-replay.log.json) |
| Merged runtime history, recorded-command replay | 20 passed | 70.075 | [History log](logs/trial-history-command-replay.log.json) |
| Upstream real runtime stop controls, recorded-command replay | 12 passed | 5.450 | [Stop log](logs/runtime-stop-command-replay.log.json) |
| Parent-owned CI contract controls | 100 passed | 40.993 | [CI contract log](logs/ci-contract-with-v4.log.json) |

The installed suite's seven skips are five original deployment controls without
independently installed native fixtures and `TRNM_CELL_BIN`, and two new actual
nonroot ELF invocation controls. This executor has effective uid 0 and an empty
effective capability set, so it cannot drop the probe child to an ordinary user.
The new recovery class alone contains seven tests: five actual file/schema/pin
controls passed and the same two invocation controls skipped. Its
[separate exact-command log](logs/recovery-class.log.json) is a subset of the
installed-host suite, not an additional seven independent trials.

The active file controls cover both pins and native size bounds, protected mode
and canonical-path checks, exclusion from each original rollback root, actual
file mutation after the first check, explicit fields/profile and exact original
flag construction. Successful recovery, native verification or installation is
not mocked. Negative mocks only fail if malformed input reaches an executable
admission path that should have been rejected earlier.

The two ELF controls use an intentionally unqualified metadata fixture and the
system `echo` ELF solely to observe held-image argv and pre-exec refusal. Even if
they run in a suitable nonroot CI context, they cannot establish a Hepta recovery
receipt, a model read or product adoption. Here they did not execute successfully.

The first attempt actually tried the child privilege transition and received
`PermissionError: [Errno 1] Operation not permitted` before owner admission. Its
[original failed output](logs/installed-host-v4-first-no-setuid.log.json) retains
`Ran 13 tests`, `failures=3`, and `skipped=5`; this includes subtest failures and
must not be reclassified as an owner/native failure or as a successful run. The
environmental precondition is now explicit in the controls. The
[earlier installed-suite output](logs/installed-host-before-new-controls.log.json)
and an [intermediate incomplete output](logs/installed-host-v4.log.json) are also
retained. The incomplete output has no terminal result and is not used to assign
pass counts. The complete final log is authoritative for the 15-test rerun.

Every log is stored as a lossless UTF-8 JSON wrapper with original byte length and
SHA-256. No whitespace, failed observation or skipped case has been stripped.
[validation.json](validation.json) binds the source hashes, target sources,
environment, commands and logs. The merged pilot retains both ledger reconciliation
and upstream child ownership for SIGINT/SIGTERM; its exact tested SHA-256 is
`59e1c14d3cd8ffd977e33502f174adebe42c9db7d0887de3c3e20abff50e0b52`.

The first evidence draft incorrectly recorded the three runtime commands with
`-s scripts/ci`. Those test files are in `scripts/`. That draft is retained as
[superseded metadata](retained/validation-before-command-correction.json), with
the command error explicitly recorded in the current validation. The three
original logs retain their complete results: [ledger 24 passed in 14.052 s](logs/trial-ledger.log.json),
[history 20 passed in 58.933 s](logs/trial-replay.log.json), and
[stop 12 passed in 5.941 s](logs/runtime-stop.log.json). Their original invocation
strings were not captured, so the corrected commands are not attributed to
those historical logs. The table instead reports new actual replays using
`python3 -m unittest discover -s scripts -p <exact-test-file> -v`, with each
command and output recorded together. The CI contract command is
`python3 scripts/ci/test_ci_contract.py`; its log was supplied by the parent
integration owner and its three current CI source hashes are retained.

All ledger/history/stop reruns overlap previously retained controls and are not
new model attempts or a restored campaign allowance. Elapsed times are test-run
observations, not a comparative cost benchmark.

## Remaining experiment 1 and 6 gates

A genuine ordinary installed-next-task run still needs the full exact Chain and
Hepta build graphs and toolchains, real `trnm-cell` and a protected reopenable
`hepta-neural-agentd`, an ordinary nonroot Agent caller, pinned base/tokenizer/runtime
and adapter tensor artifacts, original qualified selection and resource/withdrawal
descriptors, an independently operated Unix FinalUse issuer, authentic external
signed frontier/trust files, and a real later task. CURRENT, FinalUse, inference,
effect and recovery readback must come from those original owners on the same
source pair. Repository receipts and small exported metadata do not reconstruct
the absent model tensors or authorize a new trial from a spent campaign.

No full Hepta reference, installed model task, revocation/reorganization recovery
or lost-ACK reconciliation result is claimed by this handoff fix. The full Cell
succinct-proof result also remains separate and unchanged; this change neither
proves that relation nor alters the original W1 verifier.
