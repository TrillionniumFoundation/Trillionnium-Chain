# Original large-state CPU gates: exact 116a artifact readback

This checkpoint independently reads the eight original hosted artifacts for
`116a3caf6046dd0db3caf1d0797e636c35c877b8`, tree
`e07dee8cad7727845063ced35933c9408341945d`. The prospective merge is
`4f10f1858ca9dbf6fdfb55e2abce569bca21acbe` with the same tree. These are the
actual original workflow results, not a new local benchmark or a qualification
of later commits.

- [Original release CPU workflow 41686753282](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41686753282): x64 and ARM, head and prospective merge, four successful jobs.
- [Original workspace test-profile CPU workflow 41686753211](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41686753211): the same four source/architecture cells, all successful.

## What passed

The four original distinct selectors (two large-state CPU cases and two public
reactor exit controls) actually executed in every cell: **32 passing executions**.
The workspace-profile cells additionally executed their **45 selected semantic
controls each, 180 passing executions**. Each named test has one actual pass,
zero failures and zero ignored tests. These exact-selector invocations
intentionally filter the other registry entries; they are not complete runtime
suite runs. The workspace job compiled its original complete workspace,
all-target/all-feature test graph before running these selectors.

Both original CPU cases retain the admitted 8,625,548-byte parent and the
original held schedule, CPU owner and settlement checks. The authenticated
backend CPU totals below include the owner and the two joined scoped workers.
They are observations from distinct hosted jobs, not controlled paired speedup
ratios.

| Original profile | Architecture / source | First authenticated case (ns) | Supplementary authenticated case (ns) |
| --- | --- | ---: | ---: |
| Release | x64 head | 382,516,028 | 387,856,755 |
| Release | x64 prospective merge | 356,820,108 | 345,626,699 |
| Release | ARM head | 337,202,904 | 340,068,488 |
| Release | ARM prospective merge | 337,498,592 | 335,183,560 |
| Workspace test | x64 head | 672,586,359 | 668,862,792 |
| Workspace test | x64 prospective merge | 683,298,526 | 695,624,662 |
| Workspace test | ARM head | 1,445,131,776 | 1,424,432,272 |
| Workspace test | ARM prospective merge | 1,386,494,952 | 1,398,870,408 |

The first case also executes the original non-authenticated backend; those
results remain in each proof. All 24 original parity records report the actual
native result `Ok`, two started/known/finished workers, known CPU accounting,
and no live CPU refusal.

## Exact boundaries and retained failure

`host_qualified` and `all_honest_service_qualified` remain **false** in every
native parity record. This does not qualify the fixed 0.25-CPU Host, the original
4-second/16-hostile-worker business confirmation gate, the 30-second campaign,
complete workspace native tests, independent operators, economics or production.
The same 116a source still has separate failing fresh-service and campaign jobs.
No threshold, profile, timeout, selector or negative assertion is relaxed here.

`OLD_0443_ARM_FAILURE.json` preserves the earlier exact ARM workspace-profile
artifact 13254446753. Its two CPU cases fail with
`PUBLIC_MUTATION_CPU_BUDGET`, totals 2,717,055,952 ns and 2,729,240,984 ns.
Those failures remain failures. The 116a workflow and Cargo profile/lock inputs
are byte-identical to that source. The original test helper's setup/dispatch/
budget prefix and strict unwrap/settlement/reopen suffix are also identical.
The intervening helper change adds refusal readback diagnostics after the
operation and settlement; it does not turn a refused result into success.

## Reproduction and evidence

Download the eight ZIPs identified by `DOWNLOADS_VERIFIED.json` from the two
original GitHub runs while their retained artifacts are available. Save each
as `<artifact-id>.zip` beside that JSON file. Use a checkout with the exact
0443 and 116a Git objects, then run:

```sh
python3 verify_cpu_receipts.py \
  --artifact-dir /absolute/path/to/original-artifacts \
  --repo /absolute/path/to/Trillionnium-Chain \
  --output /absolute/path/to/reproduced-readback
```

The checker verifies the original ZIP lengths and SHA-256 digests, rejects
duplicate member/JSON names, limits decoding, and executes no archive or
repository source. It checks source identity before/after, actual Rust/Cargo
1.95.0 versions, original build argv/environment/profile/features, binary
hashes, exact native result lines, CPU/parity records and semantic selection.
It also compares the original source inputs and strict test portions through
Git. This is artifact validation; it does not rerun native tests.

The eight numbered proof JSONs preserve the small raw build/source/exit
receipts, original diagnostic records, actual selector outcomes and hashes of
every archive member. `VERIFIED.json` and `VERIFIER_EXECUTION.json` bind the
actual successful verification to its source and command. Raw ZIPs, executables,
SQLite databases and ephemeral download URLs are intentionally not committed.
The independent review covers source, scope and these recorded proof files;
it is not a second native execution.

**DRAFT / HOLD_NO_GO / DENY_ALL.** This checkpoint closes only the readback of
the named original CPU gates on the stated source. Broader blockers remain open.
