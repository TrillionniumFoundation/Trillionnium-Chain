# Ordered Growth execution and request-cost accounting

Status: **HOLD**. This continuation implements concrete correctness, preparation,
and observation changes. It does not qualify a common PQ/Growth/public/recovery
runtime or confirmed-business throughput.

The executed Chain source is
[`657bf2a462ff13a6101ebcb4fbe0fb91c515c972`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/657bf2a462ff13a6101ebcb4fbe0fb91c515c972),
tree `7ce7ac50f788dd421e7cc0c9ddb957ade3e8df73`. It preserves concurrent schema,
History and CI work through `dda4cc47362065819e9591f11f713933e7a853bf`.
Later integration heads contain additional production changes; the executions
below belong to the frozen source, not those later trees. The accompanying
[verification record](verification.json) and [raw-record index](records-index.json)
bind commands, source checks, logs and binaries.

## Changes and their purpose

1. **Retain an already verified multiproof within one operation.** The checked
   constructor returns the raw proof, authenticated facts and construction
   observation together. Growth account, nonce and proof reads reuse that full
   verification instead of immediately repeating it. Context/root checks and
   cancellation remain. No cross-request signature, proof or authority cache is
   introduced. Three controls establish identical wire/facts, one full
   verification instead of two, unchanged cancellation boundaries and fresh
   context/storage checks on every operation.
2. **Recheck the storage epoch after releasing the SQLite read snapshot.**
   Snapshot-local `PRAGMA data_version` can hide a foreign WAL commit. Nine
   public Growth snapshot-return boundaries now retain the original in-snapshot
   guards and add the final guard after rollback; packet and target autocommit
   reads also recheck completion. Six tests perform actual foreign commits that
   restore the original rows and require fail-closed owner stop; the API
   regression cases also verify cold reopen. The payment case first proves a
   real signed debit/credit succeeds.
3. **Pass the actual Growth header timestamp to the common M06 input.**
   Construction, admission and retained/cold replay now agree. Real ML-DSA
   expiry controls exercise timestamps 1999/2000/2001 at expiry 2000. They are
   input-boundary controls, not a combined PQ Growth network: the single
   transaction uses one actual worker even when configured maxima are 1/2/4/8.
4. **Prove canonical application after parallel preparation.** Eight signed
   dependent transactions cover reserve, receipt, shared-payer settlement,
   provider spending, common recipients and nonces. Preparation completion is
   forced into reverse order at worker counts 1/2/4/8; application remains in
   original order, joins finish before application, and only the owner applies
   State/proofs, reward, durable commit and activation. The full-State serial
   oracle and cold reopen agree. A resealed invalid order refuses atomically.
   This strengthens the existing executor; it is not a complete Block-STM
   implementation or a borrowed throughput result.
5. **Retain actual CPU settlement and request ownership facts.** The diagnostic
   `public-v3-cpu-settlement-observation-v2` carries the original owner, scoped
   worker, total, paid and residual CPU samples without another sample or debit.
   The reader retains rejected, missing, legacy, unknown and unfinished cohorts.
   A real scoped-worker cancellation control proves join and original settlement
   continue after cancellation. Budget limits and reservation authorities do not
   change. [Precise scope and the 20 new test names](request_scope.md) separate
   lifecycle wall intervals from CPU and independent confirmation.

## Exact-source validation

| Executed check | Actual result |
| --- | --- |
| New feature tests | 13 Rust passed; all 7 new Python reader tests passed within the 51-test reader suite |
| Complete Node library | **1,083 passed / 5 failed / 28 ignored**, exit 101 |
| M06 all targets/features | 253 passed / 8 ignored / 0 failed across 18 targets containing tests |
| Request reader / source-integrity / from-zero readers | 51 / 43 / 140 passed |
| Native selector roster controls | 9 passed |
| Strict workspace/all-targets/all-features Clippy | Passed with `-D warnings` |
| Graph, formatting, source inventory and repository checks | Passed; 26 workspace members, 175 resolved packages, 3,022 local links |
| Original Host readiness | Refused: `HOSTED_CI_ONLY_NO_LOCAL_PROVISION` |
| Original release F0 native runner | Five named invocations passed; **business acceptance failed** |

The original-profile Node build at `59546d6` failed with SIGKILL and remains
retained. The successful functional Node build uses only a Node test debuginfo
override (`debug=0`), with opt-level 3, debug assertions, overflow checks and
`pq-native-openssl` intact. Its fresh compiler artifact has SHA-256
`8253f1421239e28a4cbf9c520b23bbfa36f95942f94437045e4558ae41fc528c`.
That profile is not presented as an original-profile performance qualification.
The F0 build separately uses the runner's unchanged original release profile;
its SHA-256 is
`bc28532b148158a5930573570f44a2101cfca034e3f05203449882040dc8eb74`.

### The five Node failures remain failures

Three independent-witness tests fail when the child creates its pathname Unix
listener with `EPERM`, before ready and before witness records. This is not an
observed namespace syscall failure, and no witness or permission check was
bypassed. One witness test fails its original 250 ms exchange deadline during
Node creation, before the intended commit fault is installed. One inactive-page
test's diagnostic unwrap fails with `OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH`, hiding
the original receive result. The retained capped diagnostics do not establish
which cost or clock condition caused those last two failures.

The same binary/source separately passes one isolated run of each latter test.
Those two diagnostic passes neither cancel the five original failures nor prove
host-load causation. No full-suite green result is claimed.

## Fixed-owner Growth scale: original failure and one complete diagnostic retry

The original run retains exit 101: two cohorts completed, while `a64/h128`
stopped after its flushed `warmup_started` index 104 record. The stderr mirror
ends partway through that JSON exactly at byte 110592, a 4096-byte boundary.
An output I/O failure is suspected; the original errno and root cause remain
unknown. Its reader correctly returns `REFUSED` for the incomplete cohort set.
There is no observed work-search-exhaustion or native admission error code.

One diagnostic retry uses the same source, binary, nine cohorts, 4096-attempt
work search and all original assertions, in a fresh output directory. An
external monitor samples filesystem space without changing native parameters.
The original failed cohort's 105 recorded parent entries match the retry exactly.
The retry exits 0 and the original v3 reader reports
`COMPLETE_LOCAL_OBSERVATION`: **9 cohorts, 72 measured blocks, 153 returned native
stages, 9 deliberate cancellations and 9 cold reopens**. The 144 accepted returns
are 72 admissions plus 72 activations; the other nine are the planned cancelled
admissions. Every cancelled operation preserves SQL rows and active generation.

With the exact three witness owners fixed, separate successor-proof queries use
16 / 30 / 37 point reads at 64 / 1,024 / 16,384 accounts. Header callbacks retain
three windows of at most 16 ancestors. These are named local counters, not total
SQL reads, unique ancestors, total CPU or a whole-block complexity proof.
Across the nine cohorts the middle two admission samples range from 8.779 to
18.434 ms; the largest admission is 101.686 ms and remains in its cohort. Cold
reopen ranges from 53.679 to 2,813.242 ms. The slowest deliberate
cancellation is 210.997 ms and remains separate. Each cohort has eight samples;
p99 is null. Cold reopen does not mean OS caches were flushed. The external
monitor and uncontrolled host conditions prevent a controlled speedup claim.
See [the complete scale audit](growth_scale_audit.md) for all cohort values and
the retained original failure.

## Original F0: complete requests, unsuccessful independent confirmation

The unchanged runner reaches all five named tests and all three acceptance
stages. Service and sustained stages pass their validators; confirmation fails
with `CONFIRMATION_TARGET`. All three raw reports exist. Manifest finalization
completed and all five planned native invocations returned; business acceptance
remains false. A null validated
confirmation-report field does not mean the raw report is missing.

| Original observation | Baseline | Pressure |
| --- | ---: | ---: |
| Receiver request records | 95 / 95 | 549 / 549 |
| Accepted / rejected / unknown outcome | 95 / 0 / 0 | 99 / 435 / 15 |
| Submit ACKs for supporting block sequence | 7 / 7 | 7 / 7 |
| Successful History responses | 16 / 16 | 16 / 16 |
| Accepted independent page replays | 0 / 16 | 0 / 16 |
| Independently confirmed specified business transaction | **0 / 1** | **0 / 1** |
| Separately measured execution / inclusion | null / null | null / null |
| Successful confirmation latency, p99 and TPS | null | null |

All 32 independent replays return `PUBLIC_HOST_KERNEL_PARENT` in Host resolve
before actual importing begins. The current fixed-parent path is absent; the
original Host readiness check already refused local provisioning. Current
filesystem observations do not retrospectively establish the original syscall
errno. Receiver/producer databases retain height 7; independent-client databases
retain only genesis. This distinguishes received blocks from independent
confirmation and does not diagnose an algorithmic throughput limit. See
[the native audit](from_zero_native_audit.md) and
[the Host-parent audit](from_zero_host_parent_audit.md).

All **644** request records remain, with no omitted or unfinished owners.
Original CPU fields are known for **449**, unknown for **195** missing extensions;
legacy-v1 count is zero. Known total CPU is **1,015,974,161 ns**, including
**854,722,222 ns for all 435 rejected pressure requests**. The 449 known scoped
worker fields are zero in this campaign; that is not an all-system CPU claim.
There are 629 created/closed tasks and 15 requests without a created task. All
eligible post-connection wall tails are zero, so no positive tail cohort was
observed here. The independent cancellation test provides the nonzero worker
drain case. Original samples exclude reactor work and budget/journal work after
the original owner sample. [CPU and lifecycle coverage](from_zero_cpu_coverage.md)
retains those unknowns and scope limits; owner closure is not business success.

## Fixed combination and remaining gates

The observed runtime is `hepta-private-ci` #4812 at
`7530e4bc7aa61a0c23a5933fef4a65d86a586cf8`; it was not executed in this
continuation. Historical V10 remains its original Chain/runtime tuple and cannot
qualify this Chain source. The workflow still defaults to V4 with older role
pins. [Exact source-combination facts](source-combination-facts.md) retain URLs,
digests and the remaining integration boundaries.

The timestamp seam is repaired. PQ configuration sealing, classical Growth wire
and owner decoding, untouched-account authority closure, working-set authority
size, and shared network/witness/CURRENT/recovery ownership still require a
real combined profile and actual execution. Whole-host capacity reservation,
complete proof/History/Cell/recovery resource composition, original four-second
16-worker confirmation, 4,105-block History, independent operation and activation
remain open. No domain, deadline, denominator or qualification flag is weakened.

## Reproduction and retained records

[raw-records.tar.gz](raw-records.tar.gz) preserves original command receipts,
stdout/stderr, complete F0 reports and fixture databases, both scale attempts,
reader results, source/binary bindings and failed builds. The index specifies
every archived byte count and SHA-256 and explicitly identifies any excluded
executables. No failed or unknown observation is reconstructed as a success.

Use a separate checkout of the frozen commit with its locked Cargo graph and
pinned OpenSSL 3.5.9 provider. Exact native argv and recorded environment are in
each command receipt. The functional Node build is:

```sh
cargo --config 'profile.test.package.trnm-pon-node.debug=0' test \
  --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --all-features --lib --no-run -vv \
  --message-format=json-render-diagnostics
```

The fresh compiler-artifact record, not an arbitrary cached executable, selects
the binary. Run the complete library with `--nocapture --test-threads=1`.
The exact ignored scale selector is
`store::growth::tests::scale_observation::native_growth_v2_fixed_owner_account_history_scale_observation`;
set `TRNM_GROWTH_SCALE_OBSERVATION_DIR` to a new directory and retain
`--ignored --exact --nocapture --test-threads=1`. Check it with the unchanged
`scripts/ci/check_growth_scale_observation.py`. The original F0 entry remains
`scripts/ci/run_from_zero_host.py -- scripts/ci/run_from_zero_native.py` with
the Python interpreter specified for each script as recorded in the receipts;
do not fabricate hosted-CI flags or bypass its Host parent to obtain acceptance.
