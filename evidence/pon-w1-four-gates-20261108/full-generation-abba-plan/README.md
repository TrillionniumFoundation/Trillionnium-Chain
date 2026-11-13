# Full-generation matched ABBA preparation — not executed

This is a prospective preparation, not four completed proof generations. The
80 existing ABBA rows remain verification-only. This preparation starts no
expensive prover, changes no historical deadline, and does not qualify old A/C3
binaries as C4 output.

## Exact comparison to prepare

Use four newly declared full-generation trials in order A, B, B, A. A is
`--compression-mode sequential`; B is `--compression-mode balanced`. All other
requested controls are identical:

| Control | Both schemes |
| --- | --- |
| Segment workers | 1 |
| Compression workers | 1 |
| Rayon threads per worker and inherited environment | 8 |
| CPU quota | 800%, with actual `cpu.max` readback |
| CPU affinity | 12–19, with actual affinity readback |
| Memory cap | 8,589,934,592 bytes, with actual `memory.max` readback |
| New-trial research deadline | 7,200 seconds from its original local declaration |
| Verification ABBA | `--comparison-repeats 0` |
| Source, executable bytes, guest/profile | One common newly qualified C4 set |
| Candidate material, input, header and expected artifacts | One common legal Node candidate binding |
| Owner and launcher path | One common prospectively declared path |
| Checkpoint | New output directory for every trial; no segment/recursive checkpoint reuse |

The inspected source rejects sequential compression with more than one
compression worker and rejects requested workers × Rayon greater than 8. It
explicitly accepts zero verification-comparison repeats. Thus a common 1/1/8
configuration is executable without changing those source rules. This comparison
isolates compression order. It does not test the original pair of 2/2/4 versus
1/1/8 worker policies or establish a general benefit from parallel generation.

## The remaining binding is a real pre-execution gate

Before launch, freeze and qualify the actual C4 source, runner, native-winner
binary, independent verifier, guest ELF/image ID and material pins. The old
qualified A paths and digests are retained in `preparation.json` as reference
facts only. An unchanged old digest cannot silently become a C4 source attestation.
The current placeholder fields must be filled from actual C4 build/source records.

The historical material uses fixed PNH1 fixtures with placeholder parent/roots.
Repeating that expensive fixture would still not establish winning W1 Node
admission. The prospective Node-facing cohort must bind a legal candidate's
parent state, header and artifact commitments. The required native/Node checks
must independently establish that binding; a receipt alone does not supply it.

The exact new material may have a different number of execution segments. Record
actual fresh segment/lift/join counts from each new raw manifest rather than
forcing the historical number 43. If the old fixed fixture were repeated instead,
four full runs would imply 172 new segments, 172 lifts and 168 joins, but that
would remain explicitly an old-fixture study.

## Concrete argv shape

These are the existing callable interfaces, to be populated with the new C4
paths and pins after qualification. They are not launch instructions for the
unqualified old fixture.

Before every native search, the parent records a **new original** absolute Linux
monotonic deadline and boot ID. Do not reuse an old winner's expired clock. Every
subsequent prover, receiver and process observation receives that same deadline:

```text
ACTUAL_C4_NATIVE_WINNER
  PINNED_MATERIAL.bin PINNED_EXPECTED_ARTIFACTS.bin PINNED_LEGAL_HEADER_TEMPLATE.bin
  NEW_TRIAL/native-winner ORIGINAL_DEADLINE_NS ORIGINAL_BOOT_ID 10000
```

After the native output is independently checked against the common declared
statement, invoke the full pipeline for each of A, B, B, A:

```text
ACTUAL_PINNED_PYTHON ACTUAL_C4_REPOSITORY/scripts/run_w1_postwin_proof.py
  --winner-dir NEW_TRIAL/native-winner
  --out NEW_TRIAL/full-proof
  --runner ACTUAL_C4_RUNNER --runner-sha256 ACTUAL_C4_RUNNER_SHA256
  --r0vm ACTUAL_PINNED_R0VM --r0vm-sha256 ACTUAL_PINNED_R0VM_SHA256
  --verifier ACTUAL_C4_VERIFIER --verifier-sha256 ACTUAL_C4_VERIFIER_SHA256
  --segment-workers 1
  --compression-workers 1
  --rayon-threads 8
  --comparison-repeats 0
  --compression-mode sequential_or_balanced
```

The existing postwin wrapper independently replays the selected native statement,
executes fresh full preparation and proving, invokes a strict full verifier and
an independent local receiver, and binds the receiver observation to the original
winner clock. With `--comparison-repeats 0` it does not append a verification ABBA.
Its terminal and raw records must still be checked; these argv values alone do
not establish successful execution.

Use a fresh, bounded cgroup for each trial with the common quota, memory cap and
affinity. Retain observed limits, source/binary hashes, process status and resource
snapshots before/after. Do not infer exclusive CPU ownership from affinity or
quota, and do not add nested wait4 values to enclosing cgroup CPU counters.
If integrating the new collector, place it around the generation execution chain;
keep business-owner cancellation/refund/reorganization work outside the proof
command's termination deadline. GPU remains unknown unless the exact full backend
has separately passed a compatible enforcement profile; the short isolation probe
is not automatically that full-backend qualification.

## Workload and host observation

The two old full generations took 6,044.373854 and 5,939.121782 seconds. Four
serial runs of similar work correspond to roughly 23,966.991272 seconds, or
6.6575 hours. Four 7,200-second research deadlines allow up to 8 hours, apart from
explicitly ineligible bounded cleanup and report handoff. These are workload
estimates from old data, not a promise that the new common configuration or legal
C4 candidate will complete within the deadline.

The retained desktop read-only observation saw 48 logical CPUs and 131,760,804
KiB total memory, with 88,411,872 KiB available (about 84.3 GiB). The retained topology observation identifies physical packages, cores and SMT
siblings for the inspected CPUs. The complete selected 12–19 topology must be
rechecked before execution. A process-name inventory found no active matched r0vm/cargo/rustc at
that observation. The load average was around 7.7. This supports the capacity
plausibility of one 8-CPU/8-GiB trial; it neither reserves those resources nor
proves an idle/exclusive host. Recheck immediately before launch.

Run this ABBA serially. Concurrent pairs would add inter-job cache, memory and
scheduler interference and would constitute a different declared design. Do not
start it merely to replace the current verification-only count with a larger
number. This preparation deliberately does not launch the 6.6–8-hour old-fixture
study in the current turn.

## What four successful new trials would and would not establish

Four completed full fresh generations give two samples per scheme for this common
conditional statement/configuration. Retain failures and predeclare whether any
failure stops the campaign; do not replace failed rows after seeing outcomes.
The two old confounded samples are not pooled into the new matched cohort.

Even a successful n=2-per-scheme cohort does not support a population p99, a
winner-time distribution, or a general causal speedup claim. It does not establish
Node admission, WAN benefits, positive provider payment, full GPU/resource billing,
cryptographic/protocol security qualification, or passage of the original
4-second / 0.25-CPU / 2-GiB business budget. Those gates stay separate and explicit.
