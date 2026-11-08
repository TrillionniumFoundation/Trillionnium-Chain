# Complete Cell version, discovery, custody and task residency

Status: source-bound component validation. All six end-to-end qualifications
remain **HOLD_NO_GO**. No production activation, independent custody, funded
successor, ordinary model/GPU execution or Hepta FinalUse is claimed.

## Exact sources and scope

- Integration base: `9f54b05c643185a5041fc1f78cef77e95877f52a`, the head of the
  existing next-architecture candidate #791 when this branch was prepared.
- Initial implementation: `a7e3ebd7883d6b865c997e8c1cbce7576caa6f4b`.
- Reviewed implementation: `bbe7f6fbed13450922a9bac49c0c5cfafcf3cf1e`.
  This adds the complete TCV1 continuation composition and narrows the written
  current-time/withdrawal contract to the actual metadata observation boundary.
- This directory is a later evidence-only delivery. It does not relabel an
  earlier command as execution of a later commit. Both complete runs retain
  their exact source-before/source-after observations, commands and raw logs.

The executions used a shared Linux x86_64 host, Rust 1.95.0, build jobs 2 and one
test thread. The dedicated Cargo target directory was separate from the
pre-fix control worktree. [Environment details](environment-observation.json)
include the exact lockfile digests. This is not the original fixed-resource Host
contract, a multi-operator WAN experiment, elapsed-time custody qualification,
NVMe/GPU device evidence or a cross-repository Hepta adoption run.

## Six concrete changes and retained limits

| Requested capability | Candidate implementation | Remaining acceptance boundary |
| --- | --- | --- |
| Complete version commitment | TCV1 contains the whole model root, dependency edges, environment closure and exact full manifest/chunk union. CPV3 signs its SHA-512 commitment with a fresh ML-DSA-65 domain. Actual cache readback checks all declared model and environment bytes under one aggregate budget and original deadline. | The actual loader must enumerate undeclared dependencies and verify device/ABI compatibility. Existing SHA-256 payload/chunk leaves do not become a whole-system PQ128 claim. Separate CPQ1 and Hepta candidates are not merged by this change. |
| Eclipse-resistant discovery | Both classic and PQ transports schedule bounded source replies round-robin before permanent per-manifest identity admission. Signature/history checking uses receipt time; current admission retains the original expiry and deadline. | This fixes early-source quota capture, not general Sybil resistance. Already-full durable history is not erased. Authenticated query-bound bootstrap responses, independent operators and WAN qualification remain open. |
| Durable custody | Actual archive contract and complete-byte readback are compared against independently supplied policy pins. A TCV1 replica counts only when both model and environment are observed at the same original store/slot. | Domain/administrator IDs are declared owner pins, not evidence of physically independent administration or failure. Sequential local readback is not future or simultaneous availability. |
| Renewal and repair economy | Complete-version continuation pairs both component actions, payers, original expiry/repair deadlines and refusal reasons. One bounded sponsor union prevents inconsistent states for a shared owner. Missing/late component observations cannot yield a complete plan. | Work items are historical bounded planning results. Contactability is not funds; no payment, successor admission, repair dispatch, refund, lease extension or deletion is fabricated. Actual sponsors and economic sustainability remain required. |
| Loading/cache | The original network session checks RAM/reference capacity after metadata and before payload. A borrowed complete resident working set rejects absent members, charges shared buffers correctly, and has no disk/network fallback during hot reads. | This establishes task RAM admission and local access boundaries. It does not measure NVMe or allocate/read back VRAM, run an ordinary expert path, or preempt arbitrary consumer computation. |
| Current use permission | CPV3 rechecks the supplied current key, sequence, version and loader pins; task access retains original deadlines and latched cancellation. Neither download, a signature nor a returned reference grants execution. | The real owner must maintain fresh monotone current state and its resource/FinalUse guard. The metadata observation is not a durable last-time or publisher high-water ledger. Revocation cannot erase plaintext already copied by another node. |

Detailed contracts are in the [complete-version specification](../../docs/development/specs/pon/CELL_COMPLETE_VERSION_V1.md),
[discovery specification](../../docs/development/specs/pon/CELL_PROVIDER_DISCOVERY_DEV_V1.md)
and [custody/continuation specification](../../docs/development/specs/pon/CELL_CUSTODY_CONTINUATION_V1.md).
The [sole development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
retains the operational qualification gates.

## Actual complete validation results

| Exact source | Library tests | Integration/CLI tests | Compile-fail doctests | New native tests individually found successful | Command gates |
| --- | ---: | ---: | ---: | ---: | ---: |
| `a7e3ebd7883d6b865c997e8c1cbce7576caa6f4b` | 423 | 34 | 11 | 46 | 17/17 |
| `bbe7f6fbed13450922a9bac49c0c5cfafcf3cf1e` | 428 | 34 | 11 | 51 | 17/17 |

The reviewed implementation therefore has **462 native tests and 11 compile-fail
doctests passed**, with zero failed, ignored or filtered tests in the complete
crate execution. The new controls comprise 13 complete-version/signature tests,
4 discovery transport controls, 24 custody/continuation tests and 10 task/cache
controls, plus one new compile-fail ownership example. Zero-test binary targets
are retained in the raw Cargo output and are not counted as additional coverage.

The runtime command is the complete default-feature `trnm-data-availability`
Cargo test invocation. It is not an all-feature or whole-workspace runtime test.
The separate workspace lint command uses `--workspace --all-targets
--all-features -- -D warnings` and passed. Default, all-feature and fuzz Cargo
metadata were checked with unchanged lockfiles and `--locked --offline`.

The 17-command campaign also includes formatting, the independent Python TCV1
framing vector, 43 source-integrity negative controls, 37 PQ-source negative
controls, 108 CI-contract controls, the repository/Markdown-link checker,
586 exact PQ source pins, distributed source inventory freshness, whole-tree
source checks before and after, and a final clean diff. Checkers retain their
own `HOLD_NO_GO`, runtime-not-implemented and no-activation flags.

- [Reviewed-source summary](summary.json), [native outcomes](native-results.json),
  [51 required new names](required-new-tests.json), [source before](source-before.json),
  [source after](source-after.json), [complete reviewed-source logs and runner](validation-02.tar.gz).
- [Initial-source summary](initial-summary.json), [native outcomes](initial-native-results.json),
  [46 required new names](initial-required-new-tests.json), [source before](initial-source-before.json),
  [source after](initial-source-after.json), [complete initial-source logs and runner](validation-01.tar.gz).

The summaries record every exact argv, exit code, timeout outcome, elapsed time,
log length and SHA-256. A partially completed campaign is not a final PASS.
The retained runner is the observer used on this host, with its original local
toolchain/provider paths; it is not a portable installation script.

## Real red controls and unsuccessful development observations

[Development observations](development-observations.tar.gz) preserve the
original source snapshots, test snapshots, patch and stdout/stderr:

1. At unmodified discovery transport source `9f54b05...` plus only the two new
   saturation tests, both real-TCP controls **failed**: 0 passed / 2 failed /
   377 filtered. Two early bootstrap replies supplied eight valid identities
   each and filled the permanent 16-identity manifest quota before a later
   separately configured source's record competed. The assertions preserve that exact
   failure. Both controls pass in each complete implementation run above.
2. The early parallel-edit compilation failed because the task working-set/test
   files had not yet been written. A second development compile found the old
   private transport-test call still supplied `None` after the interface changed
   to a closed readiness enum. The call was fixed; neither failed observation
   is relabelled as a passing frozen-source run.
3. A development version-test invocation mistakenly shared a target directory
   with the red worktree and selected **zero tests** from an inapplicable cached
   binary. It is invalid coverage, not a test pass. The subsequent dedicated
   target selected and passed the actual 9 version tests, then both complete
   frozen-source campaigns verified every newly added test name.
4. The source-pin checker initially refused changed bytes before their explicit
   pin refresh. That refusal is retained. Later source-pin updates do not change
   any qualification flag or rewrite earlier source identities.

No timeout, TTL, bootstrap quota, response budget or high-water history was
relaxed to obtain the fixed discovery result. The receipt-time equivocation
controls additionally keep an observed same-sequence conflict visible even when
that response expires while later bootstrap replies arrive.

## Review follow-up and exact source claims

Cross-check review found two over-broad descriptions in the initial candidate.
The reviewed implementation addresses both:

- The metadata proof rejects time before its original verification time. It
  does not remember every subsequent access time. Withdrawal must reach the
  actual owner and change its current sequence or revocation view; a separate
  same-sequence withdrawn signature does not notify an old observation.
- A release-component continuation plan is not a complete TCV1 plan. The new
  composition keeps both model and environment obligations at the same target,
  distinguishes unique version payload from component reservation charges,
  and refuses an absent/late complete observation. Five new controls exercise
  actual archive outcomes and the bounded 32-owner sponsor union. The top-level
  refusal control composes a real observation with a real expired-budget error;
  it is not described as a physical deadline-race or corruption experiment.

The distributed source inventory is a Rust/Cargo/config fingerprint input,
not a reconstructable source package or a complete transitive build-input list.
The new formal fixture, like the existing closure/model-root fixtures, is
tracked by Git and checked by whole-tree source verification. Actual CI and
distributed examples compile from complete Git checkouts; no current path
reconstructs a pruned source tree from the fingerprint list.

## Provider preparation

The unchanged repository preparation script built its pinned OpenSSL 3.5.9 in a
user-owned isolated prefix. The upstream source digest and CLI sign/verify plus
wrong-message refusal succeeded. [Provider metadata](provider.json) and
[preparation logs](provider-preparation.tar.gz) retain exact identities.
No system OpenSSL was changed. This preparation did not run OpenSSL's full
upstream suite or qualify whole-chain post-quantum security.

## Artifact integrity

[SHA-256 manifest](SHA256SUMS) covers every top-level file in this evidence
directory except itself. Archive members preserve the raw observation names.
The source-specific command summaries additionally bind their individual logs.
