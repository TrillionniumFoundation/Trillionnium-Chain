# Reconstructed narrow Host fix after workspace loss

This is a new source patch over `ac469237422d43805845e8b9a6839ad14e1028e7`.
It is not asserted byte-identical to the lost local `917b1e000` commit.
The GitHub write operations did not return a success result. The remote PR head
was read back unchanged; no new hosted CI result is claimed.

The original exact-source [x64 job](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40496230600/job/122169674203)
stopped at `PARENT_ALREADY_LOADED` before its native child started.
In systemd v255, [slice_load](https://github.com/systemd/systemd/blob/v255/src/core/slice.c)
uses `unit_load_fragment_and_dropin(u, false)`; the optional-fragment path in
[unit.c](https://github.com/systemd/systemd/blob/v255/src/core/unit.c)
can mark an unconfigured implicit slice loaded. LoadState alone is therefore
not evidence of a provisioned resource owner.

The replacement requires a successful query and exactly ten unique properties.
Only this unit's inactive/dead, non-transient, unqueued, unconfigured and
unallocated object is accepted. Missing, additional, duplicate, malformed or
contaminated properties fail. Existing runtime unit files, symlinks and actual
cgroups are refused both before the query and immediately before installation.
The fixed unit digest, 25% CPU, 2 GiB memory, zero swap, finite PIDs, original
argv, unprivileged child, exit predicate and owned-child-only cleanup are unchanged.

[Fresh validation](validation.json) records 15 Host controls, 91 CI-contract
controls and 86 original-runner controls passing. Repository consistency and
diff-whitespace checks passed on the candidate. These are Python/source checks.
They do not constitute a real systemd provisioning, native service, A03, model,
post-quantum or WAN acceptance run. No Rust source or Cargo dependency changes.

The check/query/install sequence assumes the existing exclusive ephemeral CI
host. It is not atomic against another privileged controller. Actual hosted
systemd property formatting remains an unexecuted integration gate.

The prior W1, History, PQ, Hepta and independent-operator gates remain open.
