# Exact r14 policy reader repair and retained startup failure

This packet records a Python policy/observation reader repair. It does not record
a successful native pressure campaign or change any service acceptance target.

## Actual failed input

The original hosted run
[40614503458](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40614503458)
tested head `8a35529679c3d176fd7586ab1ecf4e004f25af79`, tree
`86775ecad039c09476ee3fd627c106c813209f9c`. Job `122573718397` failed in
`load_profiles()` before compilation or a native phase began. The configuration
already names r14 and preserves r13 arithmetic history, but the Python reader
required current r13, exactly four raw revisions and only r13 arithmetic.
The failure is therefore an executed startup failure with zero native phases,
not a native service failure or a pressure acceptance pass.

The complete 14-file original artifact is retained under
`original-8a355-artifact/`, alongside its GitHub metadata and original job log.
GitHub artifact `12785130172` is 9,645 compressed bytes, SHA-256
`dce757ee5f6b0da6b60cb25635890d610616f4f3c73fac7bf84791933648e5e6`.
The original systemd observation reported 107 ms runtime and 84 ms CPU before
the configuration exception. These are startup costs, not service throughput.

The local pre-edit policy suite reproduced the inconsistency: six tests ran,
one passed and five errored, with exit 1. `before.*` retains that result and its
exact source identity.

## Repair and scope

The reader now requires exactly current r14, raw history r10 through r14,
current r14 arithmetic and the separately named historical r13 arithmetic
profile. Both arithmetic identities are recomputed using their own base
revision. Old r13 records retain their original identity; mixed r13/r14 phases
remain invalid. Unknown revisions, deleted history, changed resource limits,
changed vector hashes and relabelled arithmetic bases still fail closed.

The resource configuration and Rust sources are unchanged. The original limits
remain a 2,000,000,000 ns burst, 250,000,000 ns/second refill,
100,000,000 ns start reserve and two workers. The 30-second phases, scheduled
confirmation rounds, complete request denominators, depletion requirements and
native acceptance predicates are unchanged. The workflow now checks the policy
and phase reader controls before fetching/building the native campaign.

The related Python suite ran 31 tests with 31 passes. The controls include both
actual policy generations, rejection of missing history, attempted historical
relabeling and mixed phase identities, and preservation of zero confirmations
and false acceptance in failed synthetic records. Synthetic records are only
reader controls. The repair's exact source bytes and patch are retained in
`repair-source-observation.json` and `repair-source.patch`.

`after-1.*` additionally retains a separate command-line invocation error: the
real-artifact reader controls require an explicitly pinned artifact and were
initially invoked without those arguments. That exit 2 grants no test credit.
The 31-test success is only the separately recorded `after-0.*` invocation.

The new reader also recomputes all three actual fc23 r13 phase reports. Each
matches its retained v2 derivation in every compared field, excluding only the
local input path; original input bytes and SHA-256 are checked separately. All
three retain r13 and zero of nine confirmations per run. The separate
`current-r14-reader-fc23-r13-compatibility.json` records these comparisons. A
successful readback of a failed campaign does not change that campaign's result.

Whole package 2B remains HOLD. A later hosted run must establish the actual new
phase-host layout, real budget depletion and every original honest-service
target under its own source, binary and host identity.
