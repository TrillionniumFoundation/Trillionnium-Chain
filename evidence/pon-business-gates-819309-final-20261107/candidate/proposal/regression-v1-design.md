# Ordinary Legacy admission final-root regression proposal

Base: `819309fd312298e099642e1253b1d4ba07113e98`, tree
`f9d63abb9e2931fd78e26ccb87e3a7955068f267`.

This external proposal adds one native unit test with two parallel cases. It has
not been compiled or executed. No original gate, deadline, Host policy, fixture
budget or acceptance denominator was changed, and the frozen checkout was not edited.

## Scope and exact selector

The patch adds the test-only module declaration to `store.rs` and adds
`store/legacy_admission_root_tests.rs`. The parent agent owns the separate
production proposal at the existing `persist_admission_execution` final active
root fence. This regression calls the existing private
`node.commitment_root_arithmetic.root` to warm arithmetic, so it does not depend
on either name of the parent's renamed selector.

Planned selector:

`store::legacy_admission_root_tests::ordinary_admission_final_root_rechecks_warm_active_state_and_claim`

Expected added outer test count: 1. Two fault variants are subcases of that one
test, not two separately passed native tests. Actual compilation, exact-name
execution and denominator-reader results remain pending.

## Why this reaches the last fence

The test builds genuine signed transfers and complete PNW1 packets using the
existing continuity maintenance fixture. It admits two different height-one
branches: left is activated and right remains inactive. The attempted child
extends right at height two. A small extra canonical String in the legitimate
custom genesis is carried unchanged by all commands; the genesis commitment is
recomputed using the existing fixture recipe.

An `AFTER INSERT ON blocks` trigger is selected only by the attempted child's
exact id. Its two fault cases are:

1. Replace the untouched current active-slot String `"alpha"` with the equally
   long canonical String `"bravo"`.
2. Replace the active left block's stored root claim with zero bytes.

Right's historical parent and child reconstruction use their own right-to-genesis
snapshot/delta path. Neither reads left's live KV or left's record-root claim.
Changing the active block rather than genesis is necessary for the second case:
corrupting genesis's stored root would also corrupt the historical parent path
and could fail before the final fence.

Each fault has an independent successful control with the same kind of trigger
writing the original value/root. Both trigger schemas are outside common-prefix
qualification, so both retain the original complete historical readbacks. The
control's admission must really succeed. Its callback trace is then compared with
the fault trace, which must match every original callback except the final
`BeforeDurableCommit` after the active-root fence. This is intended to show the
earlier parent/child obligations completed. That exact trace expectation still
requires native validation; a mismatch must remain a failed observation.

## Assertions and retained obligations

Both receivers warm the existing full-root arithmetic from the actual complete
active State twice. They use the same real packets and matched active/parent
States. The actual child delta is checked not to touch the probe key.

The damaged admission must return `ROOT` with the original local-integrity kind
and owner-stop semantics. It must leave autocommit restored and all original SQL
table contents equal to their before-admission snapshot, including active,
blocks, deltas, snapshots, ancestry and event rows. The child must be absent.
Fresh active and inactive-parent State reads must match their original values.

Only after proving rollback does the test remove its trigger. A cold reopen,
with no volatile arithmetic, must preserve those active/parent States and the
same durable table contents. The two remaining blocks have equal chainwork and
the original activation rule retains the already active left tip.

No cached State, prior root claim, incomplete work token or production trust flag
is introduced. `WorkCheckedPacket::verify` actually performs the complete native
proof before the existing ordinary admission method.

## Existing controls and remaining validation

The current reorg-root controls already cover warmed untouched-row corruption,
changed stored roots, original grammar errors, all tail cancellation points,
rollback and explicit Auth/Growth/PQ V2/V6 exclusions. Existing Legacy pair tests
cover trigger/schema refusal, original complete historical readbacks and
transaction replacement. Those tests do not exercise this new ordinary
admission final-fence call site with the proposed warm arithmetic.

After the frozen 819309 execution reaches its authoritative terminal state,
the parent can apply both independent patches to an isolated checkout and run
the original strict formatting/lint checks, this exact selector with the
required-native-test reader, the retained root/prefix controls, and the original
large-parent paid-admission fixture. These proposed commands have not been run.

Performance is unknown. The 2 MiB arithmetic material is shared with prior/child
full-root fallbacks; switching to active/genesis can alter partition/string reuse.
The retained 8-row/28-row History State and the 2,100 repeated large-String fixture
are different workloads. Neither this regression nor a final-root micro-cost
would establish the four-second or 4,105-block business gate.

## Source and preflight provenance

The accompanying receipt contains actual source SHA256 values, the exact
preflight result and before/after Git head/tree/status observations. The only
writes are the `regression-v1-*` files and patch in this external proposal
directory. No source, index, refs, compiler output or native fixture was changed.
