# Native NPQ3 quota continuation

Base: `7f404b3bd5064d0257fab002895799c9d6dbf7f2` (the retained NPQ2 local delivery).
This work uses a separate branch and preserves that source and its delivered
archive. It adds an explicit quota successor to address the original tag 11
consumer's inner classical signature. See the
[implementation contract](../../docs/protocol/pon-nakamoto-v1/details/NATIVE_PQ_QUOTA_V3_RESEARCH.md).

## Before native execution

The first preflight refused the shorthand `feat/` branch prefix. No source edit or
build preceded that refusal; the branch was renamed to the allowed `feature/`
namespace and the unchanged preflight then passed. The first absolute cargo-fmt
command lacked cargo on PATH and failed; the corrected invocation then exposed
missing tracked fuzz helper sources in the inherited source-only materialization.
All 165 missing non-evidence tracked files were restored from exact base Git blobs.
No missing historical evidence blob was invented or source guard weakened. The
post-materialization script's optional final codec-test edit had a missing Path
import; that edit alone was corrected afterward. These observations are retained.

`format-02`, inventory refresh/check and all 34 source-integrity negative controls
passed on their recorded intermediate source. Further source/reader/format records
bind later stages. No successful native compilation or execution is inferred
from these controls. The dedicated exact-head CI workflow is prepared; its actual
terminal source/run/attempt and tests govern later runtime claims.

The repository still has an inherited source-only checkout rather than a qualified
complete evidence checkout. Its old NPQ2 Cargo graph contains 26 workspace packages
and its existing test-profile choices remain unchanged. No local target copy or
concurrent heavyweight native build is started while the History owner holds the
shared build window.

## Review follow-up before native build

The root review identified a same-profile migration gap in the first frozen
implementation `376f3a7d707f616ba694d297830da35e7d4bd35f`. The successor retains
that commit and adds an explicit NPQ3 trusted-migration constructor and fourth
native case. It imports an actual W1-admitted old-Node checkpoint under a prior
PQ registry selected before checkpoint acquisition, claims its stable account,
then reserves/consumes a quota with that account as the actual consumer, reads
cold, and detaches/reclaims on a heavier branch. Source retirement/finality and
prior registry history remain separate external premises. This added case is
still NOT_RUN until a real terminal result is retained.

The initial offline graph used the History vendor (rusqlite 0.32.1), which cannot
satisfy this unchanged PQ lockfile (0.39.0). The matching previously retained
`native-unpacked/vendor` contains the locked versions; a fresh local Cargo home
selects it without modifying dependencies. Exact offline locked metadata then
passed for all 26 workspace members and 173 packages. The source lockfile and
original test profiles are unchanged. Formatting and the four synthetic quota
reader controls pass after the migration case was added; these are not native
execution results.

## Source review caught a fixed-profile claim decoder

A read-only review of `0fc50c0701e0bfc94faa8c48df5957956cc6b8a3` found that
`migration::apply_claim` still called the public NPQ2-only decoder after the
outer prepare had selected NPQ3 from Config. This would refuse every NPQ3 claim.
The correction calls the same explicit `decode_for_config` owner as prepare and
apply. No auto-negotiation or NPQ2 grammar change is introduced. A sixth M06 case
requires a genuine prior/new ML-DSA claim on the quota profile, verifies NPQ2's
explicit decoder still refuses those bytes, and checks nonce 7→8, current-key
installation, claimed marker, conservation and one-time consumption. Its source
checkpoint is a labelled synthetic component fixture; the separate native case
uses an actual W1-admitted source Node. This flaw was found in source review;
no unexecuted old-source failure is relabelled as a native observation.
