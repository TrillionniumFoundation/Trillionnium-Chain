# C5 real original-deadline lifecycle

**The new dispatch lifecycle is Done. Resource settlement remains Unknown.** One new isolated research operation ran real costly r0vm startup, original-deadline termination, typed M12 failure, explicit owner veto, NativeTask principal refund, real Node branch changes and independent cold readback. Its **fresh complete-proof count is 0**. Consumed resources remain null, the full original cap stays reserved, and provider payment is false.

## Exact identity and original budget

| Field | Original value |
| --- | --- |
| Source commit | 034aa74358e0a5fa33f33e83cb63669e9738da4b |
| Source tree | 8dd452c376452224602fb202940ae84fc1f84d2e |
| Provider operation | 3c722d76b352db7450c53321368b305782f25612b9ed1fb806c49c5ec7fb5c77 |
| Generation statement | 5592f86e015fe11571eecdb9594d3b35b7eeb074a1b9488cb4a50acfeb89ef7b |
| Original target job | aefb71d1b45928150c939192ce58360f34ca7f91d37ea0ce46eea83a06a8869f |
| Boot | 14f92beb-43c6-4786-839e-b57307ae8048 |
| Original deadline | 1191795668407846 monotonic ns |
| Research budget | 120,000,000,000 ns, selected once before this operation |
| CPU allocation | CPUQuota 800%; affinity [8,9,10,11,20,21,22,23]; nice 10 |
| Memory allocation | MemoryMax 8,589,934,592 bytes |
| Original resource cap | CPU 960,000,000,000 ns; GPU 240,000,000,000 ns; memory upper bound 8,589,934,592 bytes; receipt 16,777,216 bytes |
| Native principal | 1000 isolated development-genesis research units |

[Plan](raw/plan.json), [config](raw/config.json) and [launch declaration](raw/launch-declaration.json) preserve exact source/binary pins, argv and the explicit runtime environment. The guest and upstream r0vm are retained inputs. Cargo caches were reused; no cleanroom build or new guest compilation is claimed. The [source-after record](raw/runtime-source-after.json) checks the clean exact C5 source after the actual and independent cold executions.

## Actual phase order

1. **Costly startup:** first prove-batch-0000 r0vm was observed live at 1191714889146900 ns, PID 3173352/start ticks 119171360. Its ELF, parent runner, cgroup and affinity matched the original request. See [live-start observation](raw/run/owner-cancel-start/result.json).
2. **Original deadline:** the owner waited for the original deadline; no target cancel was sent and no deadline was renewed. See [wait intent](raw/run/owner-timeout-wait-intent.json) and [deadline observation](raw/run/owner-timeout-deadline-observed.json).
3. **Target terminal:** cause is original-deadline, sticky_cancel is false, exit code is -9, and finished_monotonic_ns is 1191796086929474. This is **0.418521628 s after the original deadline**. It records execution termination, **not full-proof completion**. The original direct child was waited; the known worker was absent and the observed recursive child cgroup was empty. See [terminal helper](raw/run/owner-cancel-reconcile/result.json) and [actual parent exit](raw/run/owner-cancel-reconcile-command/result.json).
4. **Typed M12 failure:** Failure Unknown with consumed null was recorded before owner veto. The original cap remained held. See [typed failure](raw/run/m12-terminal-failure-observed.json).
5. **Explicit owner action:** the owner request and local veto preceded the ordinary signed NativeTask tag 3. Canonical principal refund was 1000. Timeout itself is not refund authority. See [owner request](raw/run/owner-cancel-requested.json), [veto observation](raw/run/owner-cancel-m12-outcome.json) and [native intent](raw/run/native-cancel-dispatch-intent.json).
6. **Real branch change:** a longer branch removed Cancel, producing NativeTask Reserved/remaining 1000 and refund_claim false. Node and M12 were actually closed and reopened on that branch; M12 remained Done with unchanged readback. Empty descendants then restored the exact original signed Cancel wire, packet, operation and inclusion. No second Cancel was signed/submitted. See [reorg result](raw/run/owner-timeout-reorg-result.json).
7. **Independent cold process:** a separate process read the same operation and original deadline, observed M12 Done and the retained cap, and performed zero generation dispatches, target cancellations or NativeTask submissions. See [cold result](raw/cold-readback-01/result.json).

The [main actual result](raw/run/funded-owner-cancellation-result.json) binds the complete observed lifecycle.

## Exact original Cancel and amount

Original Cancel operation is dba9793565d7ae83790eaba3abb255fad2643d9b2d5696196a426ae289c7d83f. Its canonical inclusion remains 9106aa00fd98086ceba112c228c487398311b407bf81dd886378c2b0587f06fd.

[Wire](raw/run/native-cancel-wire.bin) SHA256: f73e5433dc740e181426a3e50fc5f4e54d19cd9a84a1c96043257f0bfcfeb17d.
[Packet](raw/run/native-cancel-packet.bin) SHA256: 6a6125eceb7916ccf4afb673e9abeaa54d4c66ea6a21de5b0a45956dc4805295.

Owner balance was 9,999,290 after Cancel, 9,998,581 while Cancel was removed, and returned to 9,999,290 after restoration. Provider balance remained unchanged. The refund amount is **gross principal 1000**; this bundle makes no new fee-decoding claim.

## Executed commands and scope

| Execution | Actual result |
| --- | --- |
| Expensive lifecycle job 1a1b9872cfc-12894-14e6 | exit 0, 1 explicit heavy test passed, 123.23 s |
| Independent cold job 1a1b98a26b8-12894-14f7 | exit 0, 1 test passed, 0.45 s |
| C5 native-winner controls | 2 passed |
| C5 verifier controls | 2 passed |

Both lifecycle jobs have authoritative complete/durable logs under raw/jobs/. The 123.23 s parent duration includes post-deadline observation, refund and reorg; the proof deadline was unchanged. Broader owner/CI qualification is published separately. Repeated qualification counts are not added together.

## Remaining boundaries

- Done means **dispatch lifecycle terminal**. Consumed remains null, resource settlement Unknown, original cap fully retained, and provider payment false.
- GPU and memory peak are null. Raw cgroup CPU counters are retained at their actual scope and are not a complete billable resource settlement.
- **Current recursive-empty does not prove every historical descendant was owned and wait/reaped.** Full historical wait/reap remains null. The independent cold reader observes retained target results and the current worker identity; it does not claim a new recursive scope measurement.
- This ordinary research Node opener does not qualify an owned SQLite I/O runtime budget domain.
- The new 120 s research budget establishes no original business-budget pass, complete fresh-proof speedup, WAN latency, real winning-W1 admission, or cryptographic/protocol production qualification.
- No public-chain transaction was sent.

## Publication allowlist

manifest.json inventories exact source paths, bytes and SHA256 for every raw file. raw-artifacts.tar.gz contains the same explicit allowlist. JSON/logs, the external driver, native header/input artifacts and original Cancel wire/packet are retained as readable originals. No SQLite database, proc environment, credential or whole runtime directory is included. The failed earlier operation remains separately preserved in [failed-operation](../failed-operation/README.md).
