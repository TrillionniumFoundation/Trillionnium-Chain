# Original from-zero CI failure and fixed Host preparation

The original required baseline failed its business confirmation target on both
architectures. The native tests returning exit zero did not establish that
target. This candidate prepares the existing Host resource parent for the same
subprocess; a future naturally triggered CI run must establish its own outcome.

## Original failed source and artifacts

The immutable source is `0c804e9f5bcf6e972bbb4524c744d4b3c8801c34`, tree
`ebd3545aac5815260ec1f94a2b9a2f383e8dd051`, in
[required run 40490734526](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40490734526).
The two failed jobs are
[x64 122143727707](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40490734526/job/122143727707)
and
[ARM64 122143727835](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40490734526/job/122143727835).

| Architecture | Phase | Signed submissions | History transport | Verified imports | Business confirmation | Import errors |
| --- | --- | --- | --- | --- | --- | --- |
| x64 | Attack-free | 7/7 | 16/16 | 0/16 | 0/1 | 16 `PUBLIC_HOST_KERNEL_PARENT` |
| x64 | Pressure | 7/7 | 16/16 | 0/16 | 0/1 | 16 `PUBLIC_HOST_KERNEL_PARENT` |
| ARM64 | Attack-free | 7/7 | 16/16 | 0/16 | 0/1 | 16 `PUBLIC_HOST_KERNEL_PARENT` |
| ARM64 | Pressure | 7/7 | 16/16 | 0/16 | 0/1 | 16 `PUBLIC_HOST_KERNEL_PARENT` |

Both original reports contain `finite_target_met=false`,
`invariant_target_met=true`, and `same_packet_sequence_in_both_runs=true`.
All five named libtests executed and returned zero on each architecture. The
unchanged post-execution validator then refused `CONFIRMATION_TARGET`. Both
original harness manifests retain `passed=false` and `execution_finished=false`.
The pressure phase used sixteen attacker workers; the original four-second
window and two-second call deadlines were not extended.

The public import path requires the fixed administrator-owned
`/sys/fs/cgroup/trnmponpublic.slice` even for loopback transport. Every network
History response succeeded, then this eligibility check refused before native
replay. The independent verifier never advanced its genesis cursor. The CI
entry point did not prepare or enter this parent. The original artifact does
not include a cgroup snapshot sufficient to distinguish a missing path from
another failed canonical-path or ownership condition. It demonstrates strict
parent refusal, not a measured throughput saturation result.

| Original artifact | ZIP bytes | ZIP SHA-256 | Members |
| --- | ---: | --- | ---: |
| `12728108214`, x64 | 7,406,718 | `a0d4851c857d8d816d66942ee51ce351bb63d37d955f73e91750892b291c16cd` | 123 |
| `12727958291`, ARM64 | 7,155,919 | `b14bbb55e2678a0f9a4b0446dc6bc0ebb4fc5218f9017c3ba60cef1ed1c6326b` | 123 |

Both downloads matched GitHub's original artifact digest and byte count. Every
ZIP member was read and checked for CRC, length, unique safe relative path and
SHA-256. Each original native execution manifest's 47 raw-file hashes matched.
The exact before/after source identities in both manifests matched the source
above. Original report bytes were retained unchanged; this directory records
their hashes without embedding duplicate multi-megabyte report JSON or binaries.

- [Original confirmation diagnosis](original-confirmation-diagnosis.json) retains
  phase denominators, exact failures, original manifest checks, and report hashes.
- [Original artifact member integrity](original-artifact-integrity.json) records
  the complete two ZIP member inventories and computed digests.
- [Original source excerpts](original-source-excerpts.json) bind the relevant
  importer, Host eligibility check, native test and CI step to the failed source.
- [Local validation](local-validation.json) records the 91 existing CI contract,
  34 source-integrity, 12 Host refusal and 7 PQ-provider control tests, with the
  exact changed and unchanged source-file hashes.
- [Separate agent source review](agent-source-review.json) records a second
  tool-agent's source inspection under the same operator. It is not an external
  audit, an independent operator experiment, or a WAN observation.

The earlier frozen 10:51 CI snapshot remains an observation of that time. This
later artifact readback adds a diagnosis without rewriting that snapshot.

## Candidate change and limits

The three existing from-zero entry points use one explicit argv wrapper:
the required cross-architecture cost step, the priority service-model step,
and the original `protocol-contract` subprocess. Their original Python command,
arguments and native selectors remain unchanged. The remaining protocol lane
commands execute in their original resource context.

The wrapper installs the exact checked-in `config/systemd/trnmponpublic.slice`,
SHA-256 `74eb36a63559bf8603c15ddd3753a1db143684a2cefd84cce5aff10a76bbd622`,
on the allocated GitHub-hosted runner. It refuses an already provisioned parent
instead of overwriting an existing administrator configuration. The original
parent limits remain CPU quota 25% with a 100 ms period, 2 GiB memory, zero swap,
zero CPU burst, and 256 tasks. It does not borrow the different 400%/16 GiB
settings used by the separate qualification workflow.

A uniquely named transient service runs with the original runner UID, GID,
working directory and explicitly selected non-secret build/source environment.
It has no delegation, no new privileges, and an empty capability bounding set.
The wrapper records actual parent path, owner, mode, device/inode, boot ID,
thread cgroup, five limits, counters and installed unit hash before preparation,
after preparation, inside before/after execution, and outside afterward. Parent
identity and limits must remain equal across these observations. Missing or
unsupported facilities, inaccessible observations, wrong membership and changed
limits fail the step. Cleanup can stop only this invocation's unique child
service; it never stops, deletes or widens the shared fixed parent.

The entire existing `run_from_zero_native.py` subprocess enters that parent,
including its formatting, build and native tests. Its original 60-second
formatting, 900-second build and 90-second per-test limits remain unchanged.
The existing workflow/job timeouts, four-second business window, two-second call
deadlines and all acceptance flags also remain unchanged. Applying the real
resource cap can expose further build or business failures; none is converted
to success or used to justify a larger budget.

No local systemd service or sysfs resource was provisioned for this patch.
Local validation consists of Python contract/refusal tests and source checks.
It does not establish that the new hosted invocation passed, that the finite
business target is attainable under pressure, that operators are independent,
or that the public chain/model loop is ready. The public importer, native tests,
original validator and source-pinned systemd unit are unchanged. The separate
original ARM rustup `cargo-clippy` provisioning conflict is also retained; this
patch does not rewrite that failure or modify the release workflow.
