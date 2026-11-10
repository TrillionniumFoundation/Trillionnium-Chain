# M14 original Host and History observations

This is a fresh offline readback of existing hosted executions, not a new native
campaign and not a runtime repair. The candidate remains HOLD_NO_GO.

Candidate: `ac8501a85a770ba34f34e1bed507ca747e5c3f8d`; tree:
`3f321d412ab7eb1f5c03f18ba21201e96a3db144`. Main remains
`dd6e1c3cbeacbdc532b0679297835b3a0aac78f0`.

## Original campaign and fixed Host diagnostic

| Execution | Result | Original denominator |
| --- | --- | --- |
| [Original campaign 42693805359](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42693805359) | 0/3 complete campaigns; 0/9 phases | Three repeats of baseline/from-zero/late-product, each 30 seconds, with 0/24/24 external actor processes |
| [Fixed Host F0 42693805049](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42693805049) | 0/6 four-second SLO successes | Three scheduled rounds in baseline and three in valid-work-root |

All three original campaign binaries build successfully. Each run exits 101;
`phase_startup_errors=[]`; full tracked-source before/after identities match M14.
Each baseline records 14 accepted full-work blocks, one confirmation inside the
30-second window out of three planned confirmations, and an unequal final
receiver/client state. Each pressure phase accepts seven full-work blocks and
records zero of the three planned confirmations. All nine phases retain
`PUBLIC_REQUEST_DEADLINE`. ACKs are not confirmations.

F0 records complete controller-resource evidence and known-empty final states
for all three owned services. Its failure is an original acceptance failure
(`NATIVE_F0_FAILED`, report validation `BASELINE_MUST_PASS`), not evidence of
uncollected processes. Baseline has one 30-second confirmation; ROOT has none;
both have zero four-second successes.

### Cost localization, without a unique root-cause claim

In campaign run 1 baseline, history RPC fetches initially take approximately
11–12 ms, while ordinary client page imports take approximately 1.8–2.3 seconds.
The complete-page import takes 6.687 seconds; first confirmation arrives at
20.984 seconds. These are actual retained call intervals, not estimated costs.

The same client owner's before/after **increments**, excluding setup, are:

| Nested stage | Calls | Thread CPU | Wall |
| --- | ---: | ---: | ---: |
| account_graph | 81 | 4.391639277 s | 18.959047942 s |
| verify_state | 111 | 4.497167827 s | 19.447311785 s |
| admission | 11 | 4.218059264 s | 18.182456585 s |
| activation | 1 | 1.128692190 s | 4.809346537 s |

The intervals overlap and must not be added. Runs 2 and 3 show similar increments.
This locates substantial cost in ordinary State/history validation and activation;
it does not establish a particular production optimization or certify its safety.
Increasing deadlines, skipping validation, moving the verifier outside the fixed
Host, or replacing the public path with a research proof path would change the
acceptance contract.

## History: two architectures and two commit identities

All four lanes use the same tracked tree above. The prospective merge commit is
`56151b7e8fc831382edfd88888705803ec101b01`. Within each architecture the complete
test binary SHA256 is also identical across head and prospective merge.

| Architecture / identity | Result | Successful imported packets | Public server lifetime observation |
| --- | --- | ---: | --- |
| x64 head | FAIL | Unknown durable count; 2,759 successful import returns | Expired at 1,800.001517493 s |
| x64 prospective merge | PASS | 4,105 | Stopped after completion at 1,504.494593877 s |
| arm64 head | PASS | 4,105 | Stopped after completion at 1,408.810965239 s |
| arm64 prospective merge | PASS | 4,105 | Stopped after completion at 1,436.791656050 s |

The x64 head log explicitly records `reason=lifetime_expired`, no earlier stop
request, followed by `IO: Connection refused (os error 111)` at `history-rpc`.
Its last successful import cursor is retained. The failed full test takes
3,217.00 seconds, including chain construction before the server starts. The
three passing summaries take 2,738.482137729 / 2,791.477705633 /
2,853.871604928 seconds respectively, including setup and post-sync checks.
These total times are distinct from public-server lifetime.

The x64 binary is
`ece8c30e4c60973f1ce6207b748157c3f9e4c8c2e7b7c323bc702d3680d276c0`.
The arm64 binary is
`e60eb96394a2c5ea8bb134c8bf0aaf570d6921786afc2b5618366b16f94eaf09`.
The same x64 binary both passes and fails in these observations. This does not
establish stable acceptance or uniquely identify filesystem, scheduler, hardware,
or protocol causes. The History path uses a legacy backend; authenticated-campaign
stage observations above cannot be assigned to it.

All three passing History summaries retain 4,105 confirmed packets, four renewals
and corrupt-active-index cold-reopen refusal. These are local loopback controls.
They do not establish WAN service, independent operators or failure domains,
storage capacity/churn qualification, or production activation. Capacity and
churn are not rerun by this offline audit.

## Reproduction and provenance

`recompute_m14.py` verifies both campaign/F0 original ZIP hashes, all 2,208
manifest-listed original files, all source identities and the original result
hashes. The two self-inventory files bring those archives to 2,210 files.
It separately opens and hashes all 16,560 original members of the four History
ZIPs, validates ZIP CRC, compares every extracted byte identity, and emits full
per-archive member inventories. No executable or database payload is omitted from
these local checks.

Outputs are `M14_HOST_READBACK.json` and `M14_HISTORY_COMPARISON.json`. The latter
retains raw source/binary identities, exact timing events, failure-location
unknowns, resource counters and per-archive inventory hashes. It does not add a
native-test count.

Original artifact IDs in run 42693804647: x64 head `13712641233`, arm64 head
`13711273994`, x64 merge `13710089902`, arm64 merge `13712350460`. Campaign artifact
`13708896865` belongs to run 42693805359; F0 artifact `13709705081` belongs to run
42693805049. Original ZIP SHA256 values and the complete member inventories are
retained in the machine-readable outputs.

The recomputation expects the original ZIPs and extracted files beside the script;
artifact URLs remain the original GitHub run/artifact URLs. A selected-file evidence
packet, if published, cannot substitute for omitted original database/executable
bytes. No original timeout, workload, assertion, qualification field or source
namespace was changed by this audit.
