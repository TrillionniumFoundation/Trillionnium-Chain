# C7 prepared operation: launch Unknown

**The C7 costly-operation lifecycle is not complete.** Preparation succeeded and produced a source-bound intent. The transport did not establish that the original heavy request launched, and no authoritative execution terminal is available. This package does not report a C7 live r0vm observation, 120-second timeout, M12 Failure/Done, refund, reorg or independent cold success.

## Bound intent and source

- Source: `40a3a45d6b8afc5c4706c5235fec47634f4aabbe`, tree `4b25e3194a0682adff40bb476f2e7c0a395639fe`.
- Prepared provider operation: `b515f62d1a8ade59f4bf3a01ae5ef774d463ed43adc129de88602555cca945c1`.
- Preparation job: `1a1ba4b4ca5-12894-198a`, succeeded / exit 0 / complete / durable.
- Prepared plan: 50283 bytes, SHA256 `3fc21976c7c60c705d12080126ebf090c81d9f01bec182b94f679fa073429591`.
- Original heavy request: `1a1ba4cf251-12894-1994`.
- Original idempotency key: `w1-c7-only-original120s-heavy-timeout-reorg-20261108-ec265b-01`.

[The prepared plan](prepared-plan.json) has `deadline_selected=false`. It declares 8 CPU, 8 GiB, two segment workers, two compression workers, Rayon 4 and one 120-second original monotonic budget, with no renewal. Those are intent and request parameters; an actual runtime allocation and monotonic deadline were **not established** for this request. [Preparation provenance](preparation-provenance.json) binds all seven completed C7 gates: 69 commands, 655 passed methods and four ignored tests. Build/source qualification does not establish operational execution.

## What was actually observed

| Step | Original result |
|---|---|
| Prepare | Authoritative successful terminal and a new immutable prepared plan |
| First heavy start response | `launch_unknown`, `Remote launch outcome unavailable` |
| Original job status | Remote private-job-directory `FileNotFoundError` |
| Exact same request and idempotency key | `reused=true`, `retried_launch=false`, status unavailable / non-authoritative |
| One bounded final current-state inspection | Successful readonly helper `1a1ba50b185-12894-19ad`; observations below |
| Final original job status | Still remote private-job-directory `FileNotFoundError` |

The exact same request was used only for the documented idempotent reconciliation. Its response explicitly states that launch was not retried. No new dispatch key or alternative shell transport was used for this operation. After the final bounded inspection, further prepare, dispatch, cancellation and cold actions were stopped.

[The final current-state record](current-state.json) observed monotonic `1204892964908336`, Unix nanoseconds `1794127226972598241`, boot ID `14f92beb-43c6-4786-839e-b57307ae8048`. At that observation:

- The original remote job directory was absent.
- The exact systemd unit had `LoadState=not-found`, `ActiveState=inactive`, `MainPID=0`.
- Its exact expected cgroup was absent, with no owned process identity observed there.
- `config.json`, `launch-declaration.json`, `run`, `research-node` and `target-state` were not seen in the operation root.
- The readonly helper sent zero signals, opened no Node and sent no Native transaction.

These are observations at the recorded times. They are **not retrospective proof that execution never occurred**, complete historical process ownership/reaping, or an authoritative terminal for the heavy job. The absent systemd unit's default `Result=success` is not an execution success.

## State and accounting limits

No actual C7 NativeReserve, M12 phase, reservation/cap ledger, consumed-resource total, principal refund, provider payment, target terminal or runtime deadline was observed. Do not infer Pending, Reserved, Done, Failure, full-cap retention or release from the prepared intent or absent files. The intended Unknown/full-cap policy remains a source/qualification result, not an observed ledger result for this launch.

The proposed principal is 1000 in a deterministic isolated research Node fixture. It is not actual C7 funding evidence. Such fixture Cancel bytes may repeat across independent C5/C6/C7 Nodes; refunds must not be added across fixtures or described as new global-chain funds. C5/C6 existing actual lifecycle evidence remains unchanged.

This attempt establishes zero new complete fresh proofs and zero confirmed heavy/cold test passes. It establishes no deployment speedup, business-budget pass, provider payment, full resource settlement or cryptographic/security qualification.

## Exact retained records

- [Summary with unknown observations represented as null](summary.json)
- [Prepared plan](prepared-plan.json)
- [Preparation provenance](preparation-provenance.json)
- [Original transport/readback records](transport.json)
- [Final current-state inspection](current-state.json)
- [Final captured API records](final-readbacks.json)
- [File inventory](manifest.json)
- [Allowlisted raw archive](raw.tar.gz)

Raw records include the original driver/preparer and source-only probe, prepared declarations, exact Unknown tool responses, the final readonly helper, and original durable child/started/exit/witness and bounded logs for prepare and final inspection. There is no fabricated child/exit record for the Unknown heavy job. Private SQLite, ELF binaries and inherited process environments are excluded.
