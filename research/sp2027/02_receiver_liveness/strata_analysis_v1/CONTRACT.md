# SP27-02 strata analysis adapter v1

This namespace is separate from the twelve frozen reader/consumer files. It
does not change the old reader, old exported inputs, old raw records, or the
SP27-06 analyzer. Its purpose is to consume the **actual** new balanced campaign
while keeping failed collection and unstarted phases visible. Code and synthetic
validation are not an experimental result or a prior Agent 06 acknowledgment.

## Version and fixed entry points

- Adapter: `sp27-02-strata-analysis-v1` in `adapter.py`.
- Audit: `sp27-02-strata-ci-audit-v1` in `../audit_strata_ci.py`.
- Native campaign: `sp27-receiver-strata-campaign-v1`.
- Existing strict reader: `scripts/ci/run_sp27_strata_controls.py`, SHA-256
  `7b7437402b19d63e22e48174ce0c24a63c8e0de8272ad2597ea7f268cc751653`.
- Frozen window reader v2: SHA-256
  `e9d49be7d060d71c4b13ef43b32568028f26fdc6e737587fc47a78457a8c1a28`.
- Original SP27-06 analyzer: SHA-256
  `9719f822394e6295a7787be0be2c8d394d25ab19e8d17be543e4145f6bae9acc`.

The audit imports and actually executes `read_campaign(input, preparation)`.
It separately observes preparation, execution, retained binary and log hashes.
The analyzer is loaded by the frozen v2 loader, which checks its original bytes.
Every receipt records the actual adapter, audit, contract and reader digests.

## Campaign denominator and stop semantics

The source plan has thirteen phases: three initial healthy controls, T/E/L/V,
a midpoint healthy sentinel, V/L/E/T, and a terminal healthy sentinel. T is the
transport/packet-codec control; E, early reject; L, late reject; V, native-valid
expensive input. This is a predeclared forward/reverse balanced order, with two
phases per pressure arm. It is not randomized. Every native window remains four
seconds; the Host retains 0.25 CPU, 2 GiB, the original permission gates and the
90-second selector timeout.

An accepted terminal report can establish attempted, completed, incomplete and
unstarted counts. The adapter imports all thirteen planned business operations
when the seven prepared packets are available. One signed transaction plus six
depth blocks is one business operation in each fresh phase ledger. An unstarted
phase receives an explicit `not_started` event without an invented timestamp.
An attempted phase without a complete raw phase is `unknown`, not zero-latency
success and not a measured failure. No pressure business result changes the
campaign's integrity requirement. A failed health sentinel or control integrity
stops the native campaign; the existing reader enforces the retained order.

If the strict reader refuses, the audit retains the exact exception, the
execution manifest's actual `exit_code`/`timed_out`, every observed raw file,
started/invoked/index/panic markers, and the first started phase without a
complete raw JSON object. Missing start files are called **not observed**, not
proven unstarted. The thirteen-phase count is then explicitly an expectation
from pinned source, and validated native counts remain null. The analysis emits
`NO_GO`; it never fabricates `native/report.json` or a collector first-divergence.
If acquisition never completed, no transaction identity is fabricated merely to
satisfy the analyzer's mandatory schedule fields. The campaign ledger remains
available and SP27-06 import is `NOT_IMPORTED`.

## Exact field mapping

| Original evidence | Analysis / frozen SP27-06 mapping | Limits |
| --- | --- | --- |
| `plan.json.planned_phases` and validated report indexes | Separate run and one planned business operation per phase | No pooling with historical pairs or the separate 3/3 health batch |
| `business-acquisition.json.signed_honest_packets` and `packet_ids` | Decode prepared transaction ID and expected block ID; verify seven packet IDs | Decoder does not execute signature/W1 verification |
| `business_started_ns` | `request_start.at_ns` in the original phase clock | The fixed 100 ms control slot is **not** a business scheduled arrival |
| Missing exact business scheduled timestamp | `schedule.scheduled_ns = null` | No reconstructed coordinated-omission latency |
| `independent_client_confirmation` | Confirmation observation with exact transaction, included block, depth, policy and work binding | ACK, head advancement and summary booleans do not create observations |
| `independent_history_page_replay` and `independent_final_confirmation_stage` | Required recorded native replay/final-stage evidence for positive attestation | Python does not reexecute the native verifier |
| Phase Host before/after records through validated index | Host attestation for that positive native observation | Raw Host identities remain available; no permissions bypass |
| `confirmation_ended_ns`, final `client_confirmed_before_original_window_end` | Strict endpoint `< 4e9` **and** original gate true | Endpoint below T with false gate stays unconfirmed; true gate at/after T is refused |
| `inputs/arm-NNN.json.requests[]` | Actual packet hex, recomputed canonical Submit body lengths | Hex character count is not network request bytes |
| `attacks[*].calls[*]` | Actual started calls, recorded body bytes, ready/lateness/status/deadline values | Offered plan, call start, receiver arrival and service load remain distinct |
| `observations.records[*].body_digest` | Match `public-request-body-v3` digest of actual canonical input body | Hello digest is a claim until successful `body_decode`; pressure-recorded digest has a different domain |
| Submit `decode/context/work/submit_result` spans plus exact diagnostics | Recompute arm stage predicate using the existing strict reader | A stage witness is not evidence of equal arrived load |
| `work_rejection.cache` | Native full replay, cached rejection, or unknown | Legacy `full_work_started` alone is not a fresh replay count |
| Observer lifecycle and `business_receive_clock` | Map accepted time only through recorded same-process clock offset | No joining of unrelated epochs |
| Per-connection queue spans and CPU fields | Separate vectors and known/unknown totals | Nested phases and whole-lifecycle totals are not added together |
| Service metrics and actual per-call fields | Preserve recorded expiration/cancellation/refusal counters and deadlines | No cancellation cause or queue depth inferred from elapsed time |
| Missing/null costs or observations | JSON null, CSV `NOT_VERIFIED`, known-count/unknown-count summaries | Null is never imputed as zero |

The confirmation flags consumed by SP27-06 are explicitly **native successful
path attestations**, matching the original exporter's scope. They are emitted
only for a positive independent observation bound to the prepared transaction,
with recorded accepted native history replay, returned final confirmation and
verified phase Host. The file SHA-256 and JSON pointer identify the unchanged raw
observation; this is not observer authentication or a fresh cryptographic proof.

## Outputs and statistical scope

`CONSUMER_RECEIPT.json` records strict-reader acceptance/refusal, original native
qualification and first-divergence, separate analysis qualification/gap, actual
source/binary/run observations, all read file hashes and all output hashes.
`phase_ledger.json` retains all thirteen slots and detailed native telemetry;
`phase_table.json` and `.csv` are reproducible summaries; `connection_records.jsonl`
preserves every retained connection, including unmatched and pre-Hello records.
When import is valid, `frozen_06_consumption/` contains actual contract, schedule,
events, strict-window decisions and outputs written by the unchanged analyzer.

The adapter uses `archival_reanalysis` because it consumes completed raw output,
the exact business schedule timestamp and complete configuration freeze remain
unknown, and it does not launch another native experiment. It does not relabel
native measurement as synthetic; only explicit unit tests use
`synthetic_validation`. The original native campaign and run identities remain
in the ledger and receipt. No significance test, causal verdict, saturation
capacity, full lifecycle cost, or publication qualification is inferred from
two phases per arm. The valid arm includes admission, execution, fork choice
and storage; it is not an isolated W1-cost intervention.

## Reproduction

From the Chain worktree root, after verifying the downloaded ZIP and extraction
identity independently:

```sh
python3 -B research/sp2027/02_receiver_liveness/audit_strata_ci.py \
  --input /absolute/verified-raw/sp27-receiver-strata \
  --out /absolute/new-analysis-directory \
  --experiment-id ci-RUN-job-JOB-artifact-ARTIFACT
```

Output paths are create-only and cannot be inside the input archive directory.
Exit 0 means a verified collected series; exit 2 means the diagnostic receipt
was written with analysis `NO_GO`. Neither exit implies a supported mechanism.

Synthetic validation:

```sh
python3 -B -m unittest discover \
  -s research/sp2027/02_receiver_liveness/strata_analysis_v1 \
  -p test_adapter.py -v
```
