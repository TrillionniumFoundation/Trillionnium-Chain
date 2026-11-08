# C8 actual costly timeout, owner cancellation, reorg, and cold recovery

This bundle records the new provider operation `a35153e046b91421e3d8d67c0d5f053b88a87f4f8ac8213f8e3ee09f5f1be1e9` on exact source `4e007a87ceecbec8d265f6a70cfd71d512a514b5` / tree `19a4f1a6e1cec5c27e595fa555b97cddc4717a3c`. The main research test passed once in **122.68 s**, then the independently launched cold test passed once in **0.32 s**. Both durable jobs exited 0 with complete, durable stdout/stderr. This is **0 new complete proofs**, **0 positive provider payments**, and **0 resource-cap releases**.

## What actually closed

One new costly generation dispatch entered actual `r0vm` segment proving under the original 8-CPU affinity, CPUQuota 800%, 8 GiB, two segment workers, two compression workers, and Rayon 4 declaration. At its original single 120-second deadline the target terminated with cause `original-deadline`. Before any owner veto, the typed M12 API recorded `Failure(Unknown)`, `consumed = null`, and retained the original resource cap. The later explicit owner veto and ordinary owner-signed NativeTask Cancel authorized the research fixture's gross 1000-unit principal refund.

A valid alternative branch removed that Cancel from canonical ancestry, restoring the Reserved row with 1000 remaining; a real Node cold reopen observed that removed state without dispatch or a new transaction. Restoring the original Cancel ancestry used the **same wire and packet**, followed by an independent process reopening the original config/operation/deadline. It observed M12 `Done`, the same canonical Cancel, and zero new generation, Cancel request, or NativeTask transaction submissions.

## Clock and ordering

All these monotonic times share original boot `14f92beb-43c6-4786-839e-b57307ae8048`.

| Observation | Monotonic ns |
| --- | ---: |
| Single deadline selection | 1210569011653932 |
| Actual live r0vm observation | 1210605351876087 |
| Original deadline | 1210689011653932 |
| Deadline reached, before target terminal inference | 1210689012186887 |
| Target termination record | 1210689304224509 |
| Typed Unknown recorded | 1210691359119848 |
| Explicit owner veto requested | 1210691361115576 |

The target termination record is **292570577 ns (0.292570577 s) after the original deadline**. This is a termination observation, not proof completion or a renewed deadline. The research test wall time includes reconciliation/refund/reorg work and is not proof latency.

## Distinct accounting boundaries

M12 `Done` describes the dispatch lifecycle. The typed failure remains Unknown, consumed resources remain null, and the full original cap remains reserved. The retained child-cgroup CPU counters are partial scope evidence; GPU time, all historical descendant wait/reap ownership, and complete resource settlement remain unqualified. The provider balance is unchanged.

The 1000-unit amount is **gross principal** in one deterministic independent research Node fixture. The Cancel wire, packet, and NativeTask identity were compared byte-for-byte with the C5 and C6 fixtures and are identical; the comparison inputs and hashes are retained in `raw/derived/deterministic-cancel-comparison.json`. These fixtures do not establish separate additive global-chain refunds, and no public-chain transaction was submitted. The observed balances are 9999290 after Cancel and 9998581 while it is removed; 1000 is not asserted to be the net account change.

The terminal target observed its child cgroup recursively empty. A later bounded read-only check found the five recorded PID/birth identities absent, both exact former cgroups absent, and the two exact jobs inactive with MainPID 0. It sent **0 signals**. Current absence does not prove that every historical descendant was reaped or fully charged.

## Qualification history remains intact

The selected coverage consists of 73 commands and 665 passing methods, with 4 ignored. The preserved first staged attempt had 31 passing methods and 1 failure because its deadline was exhausted before spawning. Its sole predeclared repeat used the same source, argv, cwd and deadline parameters and passed all 32. Across all declared ordinary qualification attempts the count remains **77 commands, 697 executed methods, 696 passed, 1 failed, and 4 ignored**. The original failure is not reclassified. Actual default settlement grace was 5 s; patching a module constant to 0.15 did not change the function's captured default. Backend's deliberate source probe exit 1 is an expected negative check, separately identified.

The two research passes here are separate from that 697-method count. GATES2, its original verification, the first-failure and unique-repeat manifests/raw streams/jobs, the declaration and wrapper, the strict owner import, and the unchanged original driver are retained. C8 caches were copied, not empty or independently clean-room rebuilt. The fixed upstream r0vm and retained guest were reused; no fresh guest compilation is claimed.

## Independent review and reading this bundle

A separate read-only review crosschecked 18 original JSON files and the two jobs' four complete output streams, totaling 22 members / 291595 bytes. It found no contradictory record within that bounded scope, re-opened no Node database, rehashed no ELF, ran no new method or operation, and sent no signal. Its immutable 8-file bundle is retained under `raw/independent-review/`; `independent-review.json` is its exact summary. Numeric timestamps establish target termination then typed Unknown then the explicit owner request. The accepted cancellation outcome has no independent timestamp, and a new cancellation journal event is not separately proven.


Start with `summary.json`; `result.json`, `typed-failure.json`, `reorg.json`, and `cold.json` are the main exact raw JSON copies. `plan.json` had no selected deadline; `launch-declaration.json` selected it once and pins `config.json`. `started.json` binds the actual live prover; `terminal-observation.json` and `current-owned-readback.json` give their precise limited observation scopes. `gates.json` retains the complete gate binding.

`manifest.json` gives every original and copied path, size, and SHA256. `raw.tar.gz` contains the same allowlisted raw files; every member's bytes were independently checked against the copied files. Private SQLite databases, executables, inherited environment and checkpoint segment/receipt bodies are excluded.

C5/C6 actual records, the two older Pending operations, and C7 launch-Unknown are unchanged. C7 is never replayed or reclassified by this C8 experiment. This bundle establishes neither complete cryptographic/protocol qualification, winning W1 Node admission, production readiness, full proof performance, nor provider payment.
