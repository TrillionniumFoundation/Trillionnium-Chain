# Original #890 campaign: scheduled completion readback

This is a read-only replay of existing failed native evidence. No native campaign was executed in this readback. Original qualification remains **HOLD_NO_GO**, with **0/3 successful campaigns, 0/9 successful phases**, and native return code **101** on each attempt.

## Source and retention

- Workflow run: https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43104547221
- Original artifact: https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43104547221/artifacts/13894656010
- Measured source: `53e1b98a7955898b9feff4778f7136c0fd0199c8`.
- Measured tree: `094ccb0afc9e7ffbbcc83f85efb6ca4ad8d54aa0`.
- ZIP: 71,025,468 bytes; SHA-256 `9a2c2250205c6a5fe18524451addf56115aafbf951d9a5c2fd3f6056988e437e`, independently matched to the GitHub artifact API digest.
- The ZIP contains 1,766 members / 522,929,063 decoded bytes. All 1,765 original manifest entries, totaling 522,609,424 bytes, were read and matched to their original lengths and SHA-256 values. The manifest is the remaining ZIP member.
- Original manifest SHA-256: `d109aff9ea3dc147ce6703f360849f398e1965c07e58c20f4593bcb54f167325`.
- During this replay, an explicit 53-file subset was retained in the execution workspace, including all three losslessly gzip-encoded original reports, root source/resource/process receipts, logs, the runner and actual binary. Every copied byte was mapped to the unchanged original manifest. This committed directory is a compact evidence record: it contains the original complete manifest, campaign result, reader outputs and replay receipts, but does not duplicate the binary or all raw reports. The original Actions artifact is required for full byte-for-byte reproduction.

## Before/after reader comparison

The executed before-reader is the exact source from the measured commit. The executed after-reader is from local commit `5eebce7271a46fb5bb735e53c12ccc0847f50ba4`, integrated without changing its bytes as commit `775913b094`. Both reader file hashes are retained in `reader-replay-receipt.json`; the source files are not duplicated in this compact record. Both readers returned zero while preserving failed native verdicts. Full outputs, empty stderr files, exact invocation arguments, dependency hashes and elapsed reader times are retained.

After removing only the additive `fixed_schedule_completion` object from each phase, the complete before and after JSON objects are exactly equal. The new diagnostic does not change original goodput, confirmation flags, resource inputs, acceptance predicates or qualification.

Reader execution time is parsing time for this replay. It is not new runtime throughput or a native optimization measurement.

## Findings with all planned slots

Across the three original runs, the 27 planned round slots are **3 validated, 9 with unknown confirmation outcomes, and 15 unobserved**. All three validated observations are the first baseline round, which replays the same transaction in separate reset experiments. They cannot be added into three distinct real business effects across runs. Attacked phases retain zero observed validated confirmations. Missing outcomes do not establish definitive zero goodput; definitive `validated_goodput_per_second` stays null for all nine incomplete phases.

| Attempt | Baseline first round: scheduled-to-enclosing-end | Baseline second round: delay before actual start | Second-round entered duration | Second-round scheduled-to-end |
| --- | --- | --- | --- | --- |
| 1 | 27.005193220 s | 23.005243084 s | 1.996569895 s | 25.001812979 s |
| 2 | 26.900482073 s | 22.900569426 s | 2.108208388 s | 25.008777814 s |
| 3 | 27.208363602 s | 23.208438732 s | 1.798272408 s | 25.006711140 s |

The second rounds were originally scheduled at t=5 seconds but entered at approximately t=28 seconds. Their confirmation outcomes remain unknown. The added accounting retains that approximately 23-second backlog; it does not convert these rounds into successes or treat their short entered duration as complete request latency. Third baseline rounds and second/third attacked rounds have no retained execution rows and preserve null timestamps.

All confirmation p95/p99 fields remain null. Enclosing round-end timing includes existing confirmation bookkeeping and does not reconstruct an exact confirmation-event timestamp. Existing observer-local clocks are not mixed with campaign timestamps. `summary.json` retains every planned outcome, identity, raw nanosecond duration and per-phase rate field.

## Reproduction

Obtain the original Actions artifact linked above and verify its ZIP SHA-256, then extract it outside the source checkout. `scripts/read_validated_business_goodput.py` accepts the full artifact with `--bundle`, the three exact `--expected-*` pins recorded above, and without `--retained-subset`. To reproduce the original retained-subset coverage fields exactly, reconstruct the 53-file subset specified by the replay receipt and retain the original binary. The source/configuration hashes and exact original invocation arguments are recorded in `reader-replay-receipt.json`; their execution-workspace paths are provenance, not portable paths. The binary is hashed and never executed by this reader. Compact evidence alone is not a full replay bundle.
