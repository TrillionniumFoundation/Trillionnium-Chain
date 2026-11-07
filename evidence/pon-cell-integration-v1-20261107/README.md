# Cell integration: source continuity, original replay and mandatory controls

This record accompanies the finite
[multimodal V3](../pon-useful-cell-multimodal-v3-20261107/README.md) and
[native Cell](../pon-native-cell-v1-20261107/README.md) records.
It preserves integration preparation and failed observations as well as successful
controls. It does not establish production activation or a new consensus work rule.

## Actual validation

| Scope | Observed result | Counting boundary |
| --- | --- | --- |
| Original Cell V1/V2 controls | 143 tests passed | Six original test files; repeated runs are not added |
| Finite multimodal V3 | 59 distinct tests; 96 distinct complete W1 proofs in final controls | Details and full materials are in the separate V3 record |
| Bounded native Cell | 12 tests; 11 distinct claim byte strings and 55 distinct complete W1 proofs | The retired-model counterfactual is included; details are in the separate native record |
| Mandatory CI contract controls | 103 tests passed on final pinned CI source | The earlier successful run is not a second set of tests |
| Raw source-integrity negative controls | 43 tests passed | Negative fixture receipts intentionally contain rejected-source results |

The final original-relation replay ran at merged commit
`09524fa469e8d989e983ae1a1100d5932ba6a9ee`, combining the original Cell V2 work
with concurrent candidate `96e1eede091153199894532c91430bfc0f8e4572`.
Every original formal Python file in that replay's source snapshot matches the
later merged source. Its interpreter was CPython 3.12.3; the independently retained
V3 controls use the explicitly pinned CPython 3.12.14 identity. These observations
do not claim that the two reference program identities are interchangeable.

The complete local worktree at `1dcd925badfef079b4d75604480463672f0b4895`
passed raw tracked-byte verification before and after the integration checks:
10,983 entries and 1,033,245,605 bytes matched its Git tree. Repository/dependency
and Markdown-link checks and the CI contract checker also passed. Later commits
add retained evidence and explanatory links without changing the tested computation.
Raw source identity checks do not execute or certify the computation themselves.

## Original-source preparation and retained failures

The first remote attempt omitted the original model fixture in its sparse checkout.
Four suites exited before executing tests. After restoring that exact fixture,
historical Git blobs were still being lazily downloaded inside the bounded source
replay, triggering the existing timeout. An attempted object prefetch also timed
out. The original commands, streams and the prefetch job capture remain retained.

The repair transferred 261 original Git source/inventory blobs from the retained
local repository, pinned to source commit
`9fedf7ecbbe07177069c030592b4e03dcffebb81`. The original object pack and file/object
manifest are in the archive. The same six suites then passed all 143 tests without
changing the model, fixture, source relation or 30-second child timeout. Preparation
time is not discarded or promoted into a work-cost qualification.

The local CI setup initially encountered insufficient shared temporary space.
An earlier run passed all 103 controls. Repeating the controls after combining the
concurrent CI change again failed during the full-source-copy setup: only the
83-byte setup-error/traceback header was retained, not the final exception text.
The separately recorded resource observation distinguishes that incomplete log
from the inference about insufficient copy capacity.

The exact final eight CI/V3 files were then transferred to the configured
HeptaRuntime desktop and checked against both their Git objects and content hashes.
All 103 original controls passed there. This remote worktree was sparse and dirty;
its result is explicitly pinned to the actual files, not claimed as a clean full-tree
identity. Native source hashes were checked unchanged before and after the operation.
An over-strict transfer-mode fence rejected an earlier attempt before any source
write; it did not execute or fail the 103 tests. Git non-executable mode and POSIX
0600 permissions are recorded separately in the successful transfer.

## Navigation

The [archive](retained-runs.tar.gz) contains the complete `raw/` tree.
The [manifest](MANIFEST.json) records every member size and SHA; the
[archive identity](ARCHIVE.json) pins the compressed bytes. The
[review index](REVIEW.json) gives the distinct counts and scope boundaries.

Within the archive, `raw/remote-prior/validation-prior-public/` contains the
original attempted and successful six-file replays; `raw/local-continuation-controls/`
contains the local source/CI checks and failures. The remote CI package and its
runtime receipts are retained as a separately identified part of `raw/`.
`raw/native-independent-material-integrity.json` independently checks the native
claim/owner/decoded-proof/packet bytes against the retained index without rerunning
the prover or treating an integrity check as proof verification.

## Gates that remain open

General multimodal encoders and arbitrary model graphs, shared proof-to-real-owner
composition, external delivery, production adoption, independent quality, and
cheapest-legal-work qualification remain open. In particular, the separate private
Hepta runtime's FinalUse/checkpoint observations do not consume these public native
or V3 proofs. Historical consensus continues to use verified protocol parent state
and consensus time; current authorization, revocation, FinalUse and atomic operation
consumption belong at the real owner's current-use boundary.
