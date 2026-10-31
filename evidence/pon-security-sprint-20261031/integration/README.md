# Integration and source identity

The previously unpublished recovery tree was published through the GitHub
connector as commit `cf84391a474ee1f3ac78f4a907bd95184b816a54`, tree
`c7609a5502641739505862f2e4cd3c1e06ce1041`, on the existing PR 557 branch.
The tree is exactly the earlier local `7da4964d` tree. The update was non-force
with expected old head `1d11f875`; branch and PR readback confirmed the new head.
The [publication binding](publication-binding.json) records the identities.

The [full cf843 source guard](cf843-full-source.json) was actually executed on
a restored complete local checkout and records 7,561 entries / 977,895,812 bytes.
The [earlier guard](source-before-sparse.json) belongs to local `7da4964d` and
retains that identity. Neither identity-only check executes native tests.

The existing PR retained a stale base SHA even after main advanced. The actual
prospective merge used current main `dd6e1c3`, but the earlier CI event named
`9fedf7e`; the unchanged ordered-parent guard correctly failed. Updating the
PR's existing base branch to the same `main` refreshed its metadata to `dd6e1c3`.
No source guard was weakened, no alternate base was selected, and the earlier
event failures remain failures. New candidate events must still verify their
actual ordered parents.

The cf843 complete-W1 receiver workflow
[41155114694](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41155114694)
succeeded. Its result precedes the new claim-precheck implementation and is not
claimed as that implementation's execution. Both admission architectures
progressed past compiler setup into the original native stage; this observation
is not a finite-service pass. Head formatting passed on both architectures.

## Integrated controls and remaining gates

The [selected hosted readback](cf843-hosted-readback/README.md) now retains the
actual cf843 native outcomes and original failures. Both V5 architecture jobs
passed. Both admission architecture jobs failed finite confirmation/service,
with actual authenticated fresh callers. Required-baseline dependency policy, a
data-availability WouldBlock and from-zero confirmation failures are independent
of the old event-base mismatch. These results do not certify the later code.

The new source has passed 97 CI contract controls, 34 source-integrity negative
controls and 36 standalone proof-reader controls. A working-candidate repository
check passed with 26 workspace packages and 1,762 local Markdown links before the
additional selected CI evidence was added. The exact locked all-features Cargo
graph resolved 274 packages/nodes and 26 workspace members. Neither graph
resolution nor source/reader tests execute native work or waive cargo-deny.
All Cargo manifests and locks remain byte-identical to cf843. Raw process
receipts and lossless stdout/stderr are under `validation/`; their before/after
bindings explicitly cover changed tracked inputs, not an invented clean-source
execution. The final committed checkout still needs its own full identity guard.

An independent integration review found the recent-batch workflow's obsolete
16-test kernel summary. It now requires all 16 original names plus the three new
controls, 19 passes, zero failures and exactly the one named ignored manual
measurement. Thirty-seven modified-workflow shell blocks pass bash syntax.
Postprocessing accepts the retained first-binary native transcript and refuses
seven missing, duplicate, renamed, skipped or wrong-summary mutations. This is
a log-reader control, not a new final-source native execution. The current
store.rs literal pin was updated to its reviewed blob; all 16 literal pins
still match actual files.

The final History native and strict Clippy gates remain pending after local
compiler signals under shared-memory pressure. Production code remains bound
to the earlier 19-control observation, but later test-only changes have their
own source identities and cannot inherit the earlier executable's identity.
No deadline, resource limit, original selector, read obligation or ordered-parent
guard was relaxed. The original admission native gate already executes the
new nonignored host-kernel controls on x64 and ARM64.

## Confirmed replay lateness at the earlier source

The [decisive confirmation readback](confirmation-lateness/README.md) distinguishes
native confirmation from its finite-window qualification. In x64's no-attacker
phase, all seven submissions finished by 2.447785492 seconds. The seventh
independent import ran from 23.387974673 to 36.373479919 seconds, after which
native confirmation succeeded at depth six with the exact required work. The
round ended at 36.571404988 seconds, beyond the unchanged 30-second window.
That is why the derived qualified `confirmed` is false despite a successful
native observation and on-time History RPCs. This localizes the overrun to an
independent import interval, not to a particular internal check or syscall.

The ordinary pool-miner MTP repair is orthogonal: the pressure fixture prepares
its packets before the phase and does not wait for `run_pool_mining`. Kernel
verification runs on the independent-import path, but the small quota-read
experiment does not establish a whole-round improvement. The separate four-
second from-zero `CONFIRMATION_TARGET` failure remains ambiguous because its
original detailed report was not present in the retrieved archives.

The focused native workflow now also executes the two mining regression cases
explicitly before its original Clippy/campaign steps; all 14 original steps and
all original job/resource settings remain unchanged. Its 13 shell blocks and
five retained-transcript/mutation controls pass. This provides an exact-head
execution route even when the main protocol-contract lane stops at its earlier
from-zero service failure. Both new test names and the two-pass/zero-ignore
summary are required; no existing gate is skipped.
