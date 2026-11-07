# W1: concrete progress on the fifteen QROM obligations

Date: 2026-11-07. Implementation baseline:
`7150d96a2112875b4afcf3023361a5cef4a0e4b1`.
Publication: [Draft PR #778](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/778),
continuing the existing W1 v2 integration branch.

**Disposition: independently reproduced implementation facts and conditional
calculations; complete-proof, authorization and quantum-work acceptance remain
separate HOLD decisions.** The original fifteen-item report is retained with
its original bytes. This continuation records narrower progress against each
item without interpreting a successful engineering test as a QROM theorem.

The [evidence index](../../evidence/pon-w1-qrom-closure-20261107/README.md)
contains the machine disposition, original publication readback, hosted source
checks, local validation and independent reviews. Four detailed analyses are
part of this continuation:

* [Binary, AIR and recursion-artifact semantics](W1_QROM_SEMANTICS_AUDIT_20261107.md).
* [All 27 bytecode-to-control-ID computations](W1_ZKR_CONTROL_ID_RECOMPUTATION_20261107.md).
* [Formal compiler/composition and joint-oracle obligations](W1_QROM_FORMAL_OBLIGATIONS_20261107.md).
* [Lifetime accounting and independent acceptance](W1_LIFETIME_AND_INDEPENDENT_ACCEPTANCE_20261107.md).

## 1. Fixed statements and actual binary binding

The saved v2 guest is a 375,928-byte R0BF composite, containing a user ELF and
a kernel ELF. The new independent reader reconstructs both load maps, applies
the specified overwrite order and suspend fields, and calculates the sparse
memory tree and final tagged SHA-256 image. Its result is
`7b8fb87437a9f1c308909d6b8e27655a3190ae04d2b11a2fa12ef111941c0dff`,
matching all eight configured image words. The locked official
`compute_image_id` implementation was also executed on the same complete file
and returned those words.

This calculation covers 208 nonempty memory pages and 51,507 loaded words.
The embedded kernel is byte-for-byte equal to the kernel binary in the complete
checksum-verified `risc0-zkos-v1compat 2.2.3` archive. The audit includes the
upstream zero-page, zero-memory and nonzero-kernel known answers.

Image identity fixes initialized memory. It does not uniquely identify every
byte of the container: a demonstrated change in a nonloaded ELF byte preserves
the image inputs but changes the complete file SHA-256. Consequently both the
image ID and complete guest-file digest remain part of the fixed profile. No
source-to-binary compiler correctness claim follows from these equalities.

## 2. Constraint arithmetic and the allowed recursion family

The independent generated-DAG interpreter tracks distinct field and mix
registers. It interprets `AndEqz` and `AndCond`, including the latter's condition
degree, and rejects unknown operations, bad bank references and forward reads.
The complete recursion DAG has 12,359 operations and the RV32IM DAG 20,202.
The returned mixed constraint in both has trace-tap degree at most five.

If trace polynomials have degree below `N`, this gives a numerator degree at
most `5(N-1)`. If that numerator is also divisible by the specified degree-`N`
zerofier, its quotient degree is at most `4N-5`. Divisibility, execution semantics
and the subsequent DEEP/FRI argument are additional premises; the syntactic
degree calculation does not establish them.

The full official ZKR ZIP was retrieved through the authorized local runtime
and verified at 59,768,781 bytes against SHA-256
`744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849`.
All 32 entries consist of canonical little-endian BabyBear words in complete
23-column rows. The default allowed family remains exactly 27 programs. At
`po2=18`, after reserving 1,024 ZK rows, each fits the 261,120 available code
rows; `join_povw` uses 261,112 and leaves eight rows.

The separate C implementation reconstructs the code commitment from actual
program bytes: inverse NTT, coefficient shift by powers of three, fourfold LDE,
23-column Poseidon2 leaves and the ordered Merkle tree. Small direct DFTs and
an independent Python permutation provide its known-answer checks. The
observed complete-family result is recorded in the semantics evidence and is
distinct from the earlier catalog-only tree calculation.

All 27 computed IDs matched their fixed catalog entries. Rebuilding the
256-leaf control tree from those computed IDs and the 229 padding leaves gave
`a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56`.
The first standalone `join` trial and the later complete-family trial both
completed without a mismatch or timeout; the complete-family trial used four
threads and took roughly nine to ten seconds per program. These timings are
implementation observations and are not quantum security parameters.

These artifact facts reduce the unchecked boundary between named programs and
their fixed commitments. They do not prove the intended relation of every
program, the source-to-ZKR compiler, or every adversarially reachable trace
size. The 229 zero padding leaves still require an argument about acceptance
and digest-zero reachability. An honest nonzero program stream is insufficient
to establish that universal exclusion.

## 3. Concrete RBR and the formal compiler remain proof obligations

The fixed profile still uses BabyBear `2013265921`, its degree-four extension,
inverse rate four, radix-16 folding, 50 sampled queries and terminal polynomial
length at most 256. A bound must cover this complete instance, its power
batching, surrounding AIR/lookup/permutation/DEEP relations, all accepted
statements, and all permitted recursive branches.

[2023/1071](https://eprint.iacr.org/2023/1071) is a positive FRI security paper.
It is not the Reed-Solomon counterexample reference. Its Johnson-regime
Theorem 4.1 uses `delta < 1-sqrt(rho)-eta` and an upper expression containing
`(1-delta)^ell`. At `rho=1/4` and `ell=50`, that term exceeds `2^-50`.
This particular sufficient expression therefore cannot certify a 97-bit RBR
input for the requested compiler. It gives no lower bound on actual W1
failure probability and is not a forgery or a 50-bit security classification.

The [formal analysis](W1_QROM_FORMAL_OBLIGATIONS_20261107.md) records the
specific CDHZ January Theorems 6.10, 8.3, 10.6 and 11.3 interfaces. The ePrint
landing page identifies a March 2 revision. Ordinary retrieval did not provide
its complete bytes; the indexed January statements and the latest abstract
are not treated as version-equivalent. The January online-extractability
argument-order discrepancy is recorded as a version/interface issue, not
declared to be an error in the latest paper.

Theorem 11.3 still needs the actual strict/relaxed committed relations,
monotone target, uniform state-restoration knowledge extractor, admissible
multi-extractor, query costs and coherent oracle-mass bounds. No numerical
substitution into that theorem is reported as a project bound.

For Theorem 10.6, the new exact-rational evaluator does execute the stated
composition expression, including enlarged query arguments and the
commutativity loss. It checks a common oracle, compatible middle relations,
parameter slices, instance-size coverage and the domain of each assumed
envelope. Missing assumptions remain unknown, even under multiplication by
zero. Its numerical examples are explicitly hypothetical, not measured or
proved error functions of W1.

## 4. Merkle encodings and stateful RNG require a joint oracle

Actual leaves, caps, node ordering, field representations, transcript phases
and challenge sampling remain part of the commitment theorem's input. Eight
stored field words do not by themselves justify a uniform 256-bit ideal
oracle. The official compiler's salted bit-string Merkle interface cannot be
substituted for the actual typed Poseidon2 construction without a reduction.

The semantics audit records a concrete equality of permutation inputs between
memory and control-node hashing after child reversal and Montgomery boundary
conversion. The two serialized results differ, but their decoded field words
agree. This is a reason to model the shared primitive consistently; it is not
an accepted-proof attack or proof that the constructed input is reachable in
every relevant protocol context.

The independent finite diagnostic isolates the inference error. Two uniform
marginals using the same ideal-function input have an equality-event gap
`1-1/M` against two independent purpose functions. For a hypothetical range of
16 elements this is `15/16`; distinct encoded inputs give the product law in
that experiment. Uniform marginals alone therefore cannot supply the missing
joint distribution or quantum extraction model. The actual permutation's
security is not inferred from this finite example.

## 5. One lifetime budget and three separate acceptance lines

The new ledger accounts for processors, successful and failed roots, recursive
nodes, offline work, adaptive strategies, delegated work and unclassified uses.
It keeps uses of a shared primitive in one declared oracle group and tracks
extractor, verifier and relation-decider overheads separately. A component
bound must remain valid at the enlarged reduction query budget, not merely at
the original adversarial budget.

The project input does not assign invented numerical caps. Its total query
budget, complete error expression, target comparison and unconditional
security bits remain null. The tool supports exact conditional union bounds
only with the declared history-uniform hypothesis; it does not convert a
per-statement marginal error into adaptive security.

Four executable examples expose lifetime resets, adaptive statement selection,
multi-opportunity target loss and the difference between chain weight and
quantum search cost. The actual consensus weight is
`floor(2^256/(T+1))`. A hypothetical square-root search advantage need not scale
with that credit. The existing full fixed-template reversible W1 circuit is a
constructive algorithmic upper bound; it is not the minimum resource lower
bound for every attacker, a physical device calibration, or a fork-choice
security proof.

The selected PQ implementation uses ML-DSA-65 and explicit authorization
contexts. That source observation and the fixed signature tests have their
own scope. They do not prove complete account migration, current owner
authority, transport/finality coverage or the computation/work claims.

| Acceptance line | Concrete object | Present complete decision |
| --- | --- | --- |
| PQ authorization | Authorized owner/key/role/generation/nonce and application scope | HOLD; no inference from proof tests |
| Complete computation proof | The exact accepted guest/VM/recursive relation and QROM error | HOLD; the full extractor and bound remain absent |
| Quantum work and chain weight | Resources, reuse, lottery, retargeting and fork-choice credit | HOLD; no lower-resource or chain-security theorem supplied |

## 6. Execution evidence and publication scope

The local GitHub publication used the configured Hepta runtime and existing
desktop Git/gh authentication. Normal pre-push checks passed, the remote
branch returned the exact `7150d96a...` head, and Draft PR #778 was created
against the existing W1 v2 branch. That first publication is separately bound
in [publication.json](../../evidence/pon-w1-qrom-closure-20261107/publication.json).

The hosted [7150 QROM run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42374726537)
passed for the exact head and ordered prospective merge
`525f75b49cf20849f5dec6a4c0e0b2a40776744f`. Their source checks independently
covered 11,052 tracked entries and 1,095,556,148 bytes before and after; both
tested trees were `c8acae01f6fed538fabd918b6d7b63da348538df`.
These records belong to 7150. They cannot be borrowed as acceptance of a later
commit merely because the later change contains evidence or tests.

The [all-checks snapshot](../../evidence/pon-w1-qrom-closure-20261107/hosted-7150-all-checks-snapshot.json)
also preserves unsuccessful unrelated or broader checks. At that readback
45 checks had succeeded, 17 had failed and 10 were still running. This is a
time-specific observation, not the eventual PR aggregate. Success of the two
QROM jobs or the two transparent-receipt jobs does not imply all required CI
is green or that the draft is ready to merge.

The new closure workflow separately checks exact head and prospective merge,
the fixed named-test roster, regenerated observations, and complete source
identity before and after. Its final completion step consumes both the actual
outcome and conclusion of every required stage. It refuses zero exit without
named completion, missing or softened failures, stale output reuse, altered
source records, duplicate JSON fields and qualification upgrades.

Small real Git fixtures exercise those positive and negative workflows,
including Python optimization mode. They do not manufacture a full-source pass
for this workstation's incomplete historical evidence. The named JSON checker
is a structural verifier, not a cryptographic attestation that arbitrary
candidate Python faithfully executed its own callbacks. The complete workflow
and independent review supply ordinary CI evidence within that threat model.

Native verification uses a frozen 7150 checkout and a separately retained
selected-source inventory, because unrelated historical evidence bodies are
absent on that host. The exact locked graphs, complete registry archive/source
comparison, fresh verifier build, saved receipt verification, native replay,
official image calculation and rejection observations are recorded as native
observations. Their narrower identity boundary is not relabeled as a complete
tracked-worktree check. Hosted complete-source verification remains separate.

The completed [native summary](../../evidence/pon-w1-qrom-closure-20261107/native-summary.json)
and [133-file raw packet](../../evidence/pon-w1-qrom-closure-20261107/native-7150-observations.tar.gz)
preserve the full observed outcome. The selected 2,462 project source,
configuration and fixture files matched 7150 before and after. The dependency
review covered 310 packages and 16,395 registry source files, comparing crate
archives against the locks and unpacked bytes against the archives. Its first
successful dependency checkpoint occurred after the v2 build, during the
workspace test; it is not a pre-compilation or hermetic-build attestation.
An earlier checksum-helper failure is retained alongside the corrected
archive-based check.

The three v2 native tests, release build, fixed receipt verification, complete
native relation replay, rejection probes, formatting and strict workspace
Clippy passed. The separate full-workspace test did not pass: it exceeded its
2,700-second budget and was terminated with exit -9 before its node harness
completed. Three named outer-harness failures are present in the original
stdout: the signed-submit disconnect test, expired-old-root recovery test and
sealed-copy rewrite test. The [independent source/log review](../../evidence/pon-w1-qrom-closure-20261107/failure-classification.json) rejects the proposed
interpretation that these were expected child-process negative controls. The
unfinished harness did not print their final panic details, so the original
run does not establish their precise causes. Counts summed from completed
child and parent result blocks are not unique full-workspace test totals.
The original timeout, failures and post-timeout process observation remain
recorded regardless of any later isolated diagnostic result.

The fixed v2 release's compiled-feature sub-scope is now complete: the resolved
`risc0-zkvm 3.0.6` features are exactly `std` and `disable-dev-mode`; default,
prover, client and Bonsai features are absent. The fresh release binary is
bound by SHA-256
`47840d410ef31fc15ea2475621c391d7091161bc8ddd030d3b4f4217bdd8c1b7`.
An actual probe linked to the same release hardened-verifier library confirms
that only the fixed Poseidon2 succinct context is configured, with no segment,
Groth16 or dev verification context. Four separate actual invocations reject
the presence of `RISC0_DEV_MODE`, `RISC0_PROVER`, `BONSAI_API_URL` or
`BONSAI_API_KEY`; their values are not exposed. Release debug information is
distinct from development-mode proof acceptance and is not claimed absent.

The new [machine disposition](../../evidence/pon-w1-qrom-closure-20261107/obligation-disposition.json)
therefore marks this observed-build sub-scope complete. It continues to retain
all fifteen original obligation identities and separately states which full
security or deployment conclusions remain outside each observation.

Local execution of all W1 Python modules passed 314 tests. A separate run
passed all 147 retained CI-contract and source-integrity tests. The 105 new
named continuation controls are a subset of those 314, not an additional
105 tests. The closure workflow also reproduces seven pinned reports and
compares their entire bytes. The full ZKR ZIP trial is retained separately;
the lightweight CI does not recompute all 27 large commitments. Its small
arithmetic controls also check the saved 27-result roster, input hashes,
native completion, field encodings and recomputed allowlist root against the
separate artifact inventory. These saved-result checks remain distinct from
executing the full large-ZIP computation again.

The sole [development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
retains the prior failures and current acceptance boundaries. This continuation
does not alter the fixed proving parameters, guest, receipt profile, native
work rule, Node admission path or production authorization.

The continuation and source-inventory repair were subsequently published as
`5c3a3c5b54f43dd1c2005c2eb744e9bcbeba6794` and
`1a14f7d4826363daefac9ec10131c66d7e70ece7`, using the same authorized Hepta
local Git channel and normal hooks. The
[publication readback](../../evidence/pon-w1-qrom-closure-20261107/publication-1a14/publication-report.json)
binds the latter's exact remote head. The inventory repair adds only the three
QROM configuration entries absent from the generated distribution roster.
The original broader required-check failures and their separate causes are
retained in the [forensics record](../../evidence/pon-w1-qrom-closure-20261107/hosted-gate-forensics-42374726461.json).
No required performance target or schema guard was relaxed to obtain a pass.

The [complete 1a14 hosted readback](../../evidence/pon-w1-qrom-closure-20261107/hosted-1a14/verification.json)
now independently verifies both QROM workflows for exact head and ordered
prospective merge `f14298a2728b22fda625267e2e4844b70f829b37`. The ordered
parents are cb114 and 1a14, and the merge tree equals 1a14's
`e08b5dcd9ae2e90d0a36cb5d85e6ce1def387e85`. Each source before/after pair
covers 11,144 tracked entries and 1,100,983,593 bytes. All 105 closure names
and all 81 implementation names complete successfully in their respective
workflows; closure also reproduces seven complete reports. The two
repository-truth/inventory jobs pass. Broader failed and still-running checks
remain in the retained snapshot, so this is not a whole-PR success claim.

The [author-source follow-up](../../evidence/pon-w1-qrom-closure-20261107/theorem-source-followup.json)
also retains the latest retrieval boundary: all four public author entries
point back to the ePrint manuscript, and Hu's homepage labels its separate
PDF link as slides; the complete PDF bytes were not obtained. Neither those
links nor the publisher's conference chapter
metadata supplies the missing complete March manuscript or resolves the
January interface discrepancy.
The subsequent [ordinary official-PDF request from the native host](../../evidence/pon-w1-qrom-closure-20261107/theorem-native-retrieval.json)
returned HTTP 403. Its recorder exited successfully after preserving that
failure; no complete paper bytes or version-equivalence claim resulted.

## 7. Subsequent native failure diagnostics and scoped corrections

The three original failures were rerun individually on the unchanged 7150
node test binary, with one requested test and one harness thread per command.
The [complete diagnostic records](../../evidence/pon-w1-qrom-closure-20261107/native-7150-failure-diagnostics/diagnostics-summary.json)
bind the binary hash and selected source before and after. The ingress test
passes in isolation. That observation does not identify the cause of its
earlier two-thread failure or replace the unfinished workspace result.

The expired-root recovery test independently reproduces a cold-replay error:
`invalid type: string "1", expected u8`. Root role IDs are represented as
JSON object keys. Direct `serde_json` decoding converted those keys, but the
internally tagged Publication/Record buffering path lost that conversion.
The correction explicitly decodes canonical decimal `u8` keys, refusing
duplicates, noncanonical spellings and overflow. Serialization, root/schema
fields, signing messages, dual-quorum verification and the complete
`Root::kernel()` authority checks remain unchanged. Three new regressions
exercise the actual nested record path, malformed keys and semantic root
rejection; the original disk cold-replay test is unchanged.

The [independent mechanism probe](../../evidence/pon-w1-qrom-closure-20261107/root-role-decode-probe/summary.json)
reproduces the old error from the exact old declarations and confirms that
the revised decoder round-trips bytes produced by the old serializer. This
small probe and independent source review are not substitutes for the full
crate regressions on the new committed candidate.

The sealed-copy failure has a different explanation. The [native syscall
probes](../../evidence/pon-w1-qrom-closure-20261107/native-7150-sealed-fields/test-correction.json) observe that a denied write can still change `mtime` and `ctime` on
the tested kernel, while its content, extent, ownership, mode and seal set
remain unchanged. The existing production identity check correctly refuses
that changed snapshot. Its test incorrectly assumed that every rejected
write also preserved timestamp identity. The correction keeps the source
replacement/copy positive case separate from operations on the sealed
descriptor, and adds actual metadata-drift rejection controls. The production
identity comparison and all seal/mode checks are retained.

The separate [source-pin follow-up](../../evidence/pon-w1-qrom-closure-20261107/source-pin-followup/refresh.json)
also corrects the stale inventory fingerprint left by 1a14, and updates only
that generated inventory plus the four reviewed release-owner source/test
files. All 688 exact blob pins now match. The original source guard and
inventory checker pass without changing their implementations or any
HOLD/acceptance fields. This repairs source bookkeeping; it does not certify
cryptographic authority or resolve unrelated broader CI failures.

The new source-bound native regression results must be recorded separately
from both the original 7150 failure and its isolated diagnostics. No successful
targeted follow-up can certify the unfinished full workspace or discharge the
separate PQ authorization, complete-proof and quantum-work obligations.
