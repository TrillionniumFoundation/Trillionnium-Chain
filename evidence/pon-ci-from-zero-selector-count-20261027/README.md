# Preserve all five from-zero rejection controls

The original Hepta paired run
[40491440610](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40491440610)
failed its four Linux jobs at the existing Python from-zero boundary checks.
Three mock expectations still described four native selectors, although the
unchanged runner already executed five. The later model steps were skipped;
this correction does not turn those skipped steps into executed evidence.

The original Hepta head is `2bfceaa3226611a72f43d24e67d13e30091c7449`.
Its pinned Chain PR head is `0c804e9f5bcf6e972bbb4524c744d4b3c8801c34` and
prospective merge is `e22045b22fcda846d826243210c998a97d4559a3`.
[Original decoded-log references](hepta-original-log-references.json) retain the
four job IDs, complete UTF-8 byte counts and SHA-256 values. These are exact
connector-decoded log contents, not a claim to original GitHub ZIP bytes. The
complete logs are preserved separately without duplicating them in this patch.

The fifth selector is
`from_zero_signed_business_reports_confirmation_in_original_pressure_window_against_same_packet_baseline`.
The [source audit](selector-source-audit.json) independently lists all five names,
checks the runner's literal AST inventory, finds the original native test
definition, and compares it with the original x64/ARM artifact execution lists.
The runner is byte-identical to both the failed Chain source and correction
parent `176822ae27692aefb288f62d751695501da5c0f0`. Those original native tests
returning zero still did not satisfy the separately retained business target.

Only three fixed expectations change: the zero-match and ignored-test vectors
each gain the fifth expected `true`, and the nonzero-exit case requires exactly
five recorded runs. Each case still requires the overall result to be false.
The assertions are not replaced with the runner's own inventory length, no
assertion is removed, and no selector or native acceptance predicate changes.

The full original 86-test Python suite was replayed before and after this edit:

| Source state | Result | Retained record |
| --- | --- | --- |
| Clean parent `176822ae` | 86 executed, three failures, exit 1 | [Before metadata](before.json), [complete log](before-176822ae.log) |
| Candidate with the three fixed expectations | 86 executed, zero failures, exit 0 | [After metadata](after-86.json), [complete log](after-86.log) |

The same successor also forwards the caller's explicit, non-secret
`RUSTUP_TOOLCHAIN` through the Host wrapper. Hepta's original call selects
`1.95.0`; the wrapper preserves that value. Its existing argv test now requires
the exact `--setenv=RUSTUP_TOOLCHAIN=1.95.0` argument. All twelve Host controls
pass. The original public parent, resource caps, UID/GID, native commands,
selectors and deadlines are unchanged.

These are Python refusal/mock controls and source checks. No Hepta Rust command,
local systemd operation, native benchmark, model training or FinalUse execution
was performed for this correction. A future naturally triggered paired run must
produce its own native and model outcomes; it may still legitimately fail or
produce no update.
