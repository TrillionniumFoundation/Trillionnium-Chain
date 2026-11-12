# Original service-liveness evidence, independently read back

**HOLD / NO-GO.** This directory reads the unmodified original campaign artifact
from source `53e1b98a7955898b9feff4778f7136c0fd0199c8`. It contains no newly
executed native campaign, no relaxed deadline and no release qualification.
The original artifact, source/tree identities and resource limits are pinned in
[artifact-identity.json](artifact-identity.json).

## Results and their different meanings

The reader streamed and checked all 1,766 ZIP entries, including the complete
1,765-payload manifest covering 522,609,424 uncompressed bytes. It checked the
original source-before/source-after guards and retained the original limits:
0.25 CPU core, 2 GiB memory, no swap, 256 PIDs and three 30-second phases per
campaign, with 0/24/24 requested attackers. The original ZIP is 71,025,468 bytes,
with SHA256 `9a2c2250205c6a5fe18524451addf56115aafbf951d9a5c2fd3f6056988e437e`.

| Observation | Result | Meaning |
| --- | ---: | --- |
| Complete original campaigns | 0 / 3 | Original completion gate remains failed. |
| Complete original phases | 0 / 9 | The no-attacker baseline also failed. |
| Timely planned confirmations | 3 / 27 | All three refer to one fixture transaction. |
| Receiver/client final state equality | 0 / 9 | Complete History convergence was not demonstrated. |
| Successful History RPC responses | 47 / 47 | A response is distinct from successful native import. |
| Successful native History imports | 41 / 47 | Six imports returned `PUBLIC_REQUEST_DEADLINE`. |
| Submit attempts with an in-window successful ACK | 80 / 83 | An ACK is distinct from durable business completion. |
| Receiver records with `full_work_accepted=true` | 82 | Every one matches an original honest submitted body digest. |
| Receiver records with full-work failure | 13,851 | This does not by itself prove service availability. |

[original-readback.json](original-readback.json) is the output of the exact
retained reader from `a450df7fbf1149e62b9470b81e6a0e1b07834e25`.
[phase-counts.json](phase-counts.json) adds per-phase counts derived directly
from the three original `report.json` payloads. Their individual sizes and
SHA256 values are included in that result. All accepted records are matched
against the original honest request-body digests; unmatched accepted records,+dropped receiver records and measurement failures are zero in this archive.
This is evidence about these recorded requests, not a universal proof of
cryptographic security or of all possible attack inputs.

The three recorded confirmations carry neither finality nor execution
authority. They all identify transaction
`c6ee62ac00fdec64b6823d4ddeece3106dc969616053730e52750ecdfb4ebf21`.
They must not be described as three distinct payments or external effects.

## Baseline timing and checkpoint attribution

The first baseline confirmation in the three runs ended at respectively
28,005,193,220 ns, 27,900,482,073 ns and 28,208,363,602 ns. The original phase
limit is 30 seconds, leaving approximately 1.79–2.10 seconds for the remaining
planned work. Thus this archive does not support attributing every failed
phase exclusively to attacker pressure. It preserves a baseline completion
defect as well as the pressure-phase failures.

The original native History observations record 460,850 checkpoint calls,
27,882,321,411 ns of checkpoint calling-thread CPU and 32,816,862,268 ns of
importer calling-thread CPU. The ratio is approximately 84.96%. These counters
overlap: the checkpoint work is nested inside the importer. They must not be
added together or treated as a measured removable fraction. All recorded
History owner modes are `exclusive`; this archive does not measure a shared
owner scheduling regime.

All three Submit attempts without a timely ACK occurred in the no-attacker
baseline and returned `IO: Resource temporarily unavailable (os error 11)`
after the window. Two have a matching receiver record with
`full_work_accepted=true`; the third has a null full-work result. Their matched
records all have `dispatch_accepted=false`. These observations do not establish
durable commit or any external side effect. Unknown delivery outcomes remain
an operation-reconciliation problem; this analysis grants no retry authority.

## Reproduction

Obtain the original artifact `13894656010` from
[workflow run 43104547221](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43104547221).
Use the unmodified ZIP as `ORIGINAL.zip`. The archive is retained by that
workflow; it is not copied into this source change.

```sh
readback_dir="$(mktemp -d)"
gzip -dc evidence/chain-system-security-20261111-306929/liveness/pq_root_campaign_readback.py.gz > "$readback_dir/pq_root_campaign_readback.py"
gzip -dc evidence/chain-system-security-20261111-306929/liveness/test_pq_root_campaign_readback.py.gz > "$readback_dir/test_pq_root_campaign_readback.py"
python3 "$readback_dir/pq_root_campaign_readback.py" \
  ORIGINAL.zip \
  --expected-head 53e1b98a7955898b9feff4778f7136c0fd0199c8 \
  --expected-tree 094ccb0afc9e7ffbbcc83f85efb6ca4ad8d54aa0 \
  --expected-artifact-sha256 9a2c2250205c6a5fe18524451addf56115aafbf951d9a5c2fd3f6056988e437e
python3 evidence/chain-system-security-20261111-306929/liveness/phase_counts.py ORIGINAL.zip
python3 -m unittest discover \
  -s "$readback_dir" \
  -p test_pq_root_campaign_readback.py -v
```

The retained reader and its test file are lossless gzip payloads of the exact
upstream bytes, including their original trailing blank line. Their raw Git blob
identities and both raw/compressed digests are recorded in
[reader-payloads.json](reader-payloads.json). The initial precommit whitespace
check returned exit 2 for those two trailing blank lines. Compression preserves
the original files without changing the whitespace gate or rewriting the reader. Thirteen reader controls actually passed,
as shown by [reader-tests.stderr](reader-tests.stderr). Those Python controls
check the evidence reader. They are not a new native liveness campaign.

## Remaining qualification

The acceptance criterion remains honest confirmation and complete History
import under the original total resource and timing bounds. Per-identity,
per-connection and worker-local budgets are insufficient to establish that
criterion across multiple identities, changing challenges or recipients.
No total-lifetime attacker failure bound, independent custody, WAN result,
real external-effect reconciliation or production activation follows from
this readback.
