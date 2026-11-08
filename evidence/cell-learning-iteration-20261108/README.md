# Frozen Hepta iteration to original next use

**Scope: native engineering controls and a separate material reader. Complete
PoN-funded Hepta evolution remains HOLD_NO_GO.** This increment closes an
evaluation-profile substitution gap and joins the original learning checkpoint
to its original generation actor's first-use records. It does not exercise
funding, W1 work verification, M12 dispatch, settlement or physical model loading.

## Exact sources

- Chain parent: `e02126dabef04f13792dec45d96ac5d6916d0651`, tree
  `94752a3e02a6a8d53d4b98ea7bb7bf75216cc4da`, existing
  [#787](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/787).
- Native tested Hepta: `4a93aaf01a594258bcc3e65a1a37ac772675be63`, tree
  `f9375fd1dc5f9151a8337fc51b0c6f574049f198`, `codex-rs` subtree
  `3e7f1024a78aad91438496cf70008d2caaf1faa0`,
  [#5357](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/5357).
- The first Hepta candidate `f6247df765bb82d18247ed7d492635d09d2bb403`
  stopped at compilation. Its failures are retained separately; none of its
  cached binaries or failed commands is counted as a passing run of `4a93`.

[selected-sources.json](selected-sources.json) records immutable source and
scope pins. Chain publication uses the exact parent tree plus an explicit file
allowlist. The local Python test workspace is a selected-file reconstruction;
its unrelated Git HEAD is not represented as the tested native or published
Chain source. Existing reader and dependency files are checked against their
original parent blobs before use. Hosted head and prospective-merge gates are
separate and must be assessed at their own immutable commits.

## Observation records

The source-identical native run executes a frozen registry of **39** unique
tests, including six new profile/recovery controls. Three additional original
direct-owner controls use a separate registry and result, so their denominator
is not folded into the first run. The Chain suites exercise the independent
reader against the native paired corpus and retain the original v1 suite.

| Executed selection | Result | Limits of the result |
| --- | --- | --- |
| Primary native batch | 39/39 passed; no selected failures, errors or skips | 823 other tests were outside this focused selection. |
| Separate direct-owner batch | 3/3 passed; no selected failures, errors or skips | A distinct run ID and exact registry; 859 other tests outside its selection. |
| New checkpoint/readback join controls | 25/25 passed; no skips | Structural reader regression against the exact native engineering corpus. |
| Existing v1 readback controls | 26/26 passed; no skips | Original test blob and original reader validation prefix preserved. |

The following paths hold the observed command, outcome, exact test names and
original output. A successful capture is not itself a test-pass declaration.

| Evidence | Record |
| --- | --- |
| Native 39-test result and exact command | [native-result.json](native-readbacks/native-result.json) |
| Original native JUnit | [native-controls.junit.xml](native-readbacks/native-controls.junit.xml) |
| Frozen 39-test registry | [expected-native-test-names.json](native-readbacks/expected-native-test-names.json) |
| Independent result/JUnit/log/source check | [capture-validation.json](native-readbacks/capture-validation.json) |
| Exact exported bytes and original log offsets | [fixture-manifest.json](native-readbacks/fixture-manifest.json) |
| Separate direct-owner run and raw artifact index | [index.json](direct-owner-controls/index.json) |
| Independent join and retained-reader tests | [results.json](validation/results.json) |
| Original input blobs and explicit publication source audit | [publication-input-audit.json](validation/publication-input-audit.json) |
| Original runners and registry audit | [index.json](provenance/index.json) |
| Failed original compile attempts | [index.json](failed-attempts/index.json) |
| Post-test maintenance attempts and exact source relation | [index.json](maintenance/index.json) |
| Successful existing Windows security workflow at `4a93` | [index.json](hosted-windows-4a93/index.json) |

Post-test maintenance first ran on the tested `4a93` source: scoped `just fix`
passed, plain `just fmt` returned success without selecting files on the clean
checkout, and strict Clippy refused two intentional duplicate module inclusions
used only by tests. All source diffs stayed empty. That failed attempt remains
in `maintenance/attempt-01/`.

The successor `ed1ea5691798a2dbffbbcc8216f2929e67724af7` adds only two local
`clippy::duplicate_mod` attributes with explanations, eight lines in total.
Its tree is `a1029394b64ef1f0ac46511716dba6892fdbb261`; its `codex-rs` subtree
is `b710c1c49dc42598b79206dfdd37708da506f114`. A separate guard verifies its
direct `4a93` parent, exact two-file delta and byte-identical tested source
after removing those attributes. No production API, validation logic, fixture
bytes or test names change.

On that exact clean successor, scoped `just fix`,
`just fmt --base f1785ca15e41e4e49509a5b211a659e3cbdbf60e` and strict scoped
Clippy with `-D warnings` all passed. The explicit-base format command actually
selected the 16 changed Rust files. Source before/after and every recorded diff
were unchanged. `maintenance/attempt-02/` retains this separate result. Native
tests were not rerun after maintenance; the 39 + 3 executed cases and paired
exports remain explicitly pinned to `4a93`.

Native compilation and tests use Rust 1.96.0 and the repository's original
`just test` entry point. The isolated build envelope is two CPU cores and
8 GiB memory; it is an engineering test allowance, not a measurement or
qualification of the smaller production execution budget. A warm build cache
is not provenance: the source tree, actual run ID, frozen exact-name registry,
JUnit case outcomes and raw output commitments must all agree.

The first build omitted `docs/modules/MODULES.json` from a sparse checkout.
The second still omitted the included proposal worker and exposed nine
ambiguous `assert_eq` macro uses in a new test module. Both exited before
executing any selected test. The corrected source adds an explicit
`pretty_assertions::assert_eq` import and six argument labels, and the successful
attempt uses a complete tracked checkout. The hosted
[Windows run at f6247](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/42478192065)
independently reported the same macro ambiguity; its status is not borrowed by
the corrected source.

GitHub subsequently reports the existing Windows private-state security
qualification [run 42480262145](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/42480262145)
as completed successfully at the exact corrected `4a93` source. The returned
workflow/job JSON records all steps successful, including Agentd integration,
native directory-attack refusal and final source checks. This is a separate
hosted workflow observation, not a claim about its uncounted test denominator,
later source heads or complete Windows production qualification.

## Capture and independent replay

[extract_native_pairs.py](tools/extract_native_pairs.py) verifies the native
result, clean source before/after, exact tree, log and JUnit digests, one actual
Nextest run ID and the complete frozen test denominator before calling
[capture_native_learning_exports.py](tools/capture_native_learning_exports.py).
The collector copies each exact JSON slice from the original stdout, decodes
the canonical unpadded base64 checkpoint and recomputes the production codec's
initial and receipt heads using the separate Python implementation.

Each phase has six files: original readback JSON, raw `HEPLCP02` checkpoint,
original checkpoint export JSON, fixture-derived expected context,
fixture-derived frozen request and the material-review result. The phases are
`retained_pending`, `retained_acked`, `adopted_pending` and `adopted_acked`.
These are **two engineering cases at two times**, not four independent model
experiments. Original JSON document bytes are not rewritten. Log byte offsets
refer to the stored original stdout bytes.

Expected context and freeze files in this corpus are explicitly fixture-derived.
They allow independent decoder regression, but do not prove that an independent
owner retained these pins before training. Production use must obtain the
original freeze independently. The reader accepts all four checkpoint/freeze
CLI arguments together or refuses; omitting all of them retains the existing
v1 review scope. The command and format are documented in the
[integration specification](../../docs/development/specs/pon/CELL_LEARNING_ITERATION_JOIN_V2.md).

## Meaning and remaining gates

The join binds the full original request, incumbent bundle, evaluation profile,
budget, envelope and owner IDs through native learning receipts to Selection
and the corresponding original first-use materials. Its checkpoint ends at
Selection, before the learning owner accepts NextUse. Pending delivery, ACK and
model stop do not themselves complete that learning iteration.

The report preserves `DENY_ALL`, `NOT_EXPORTED` and `HOLD_NO_GO`. In particular,
the following remain unestablished by these engineering results:

- Independent pre-dispatch custody, authenticated learning signatures and
  actor-to-controller association.
- A complete production `LearningIterationOwnerPortsV1` adapter, actual
  training and independent no-change/cell-only/routing-only/joint evaluation,
  protected holdouts, retention and interference results.
- Original funded Task/M12 execution and complete resource charges, fresh
  qualified work, canonical confirmation, real payment and reorg reconciliation.
- Protected physical installation, actual neural loading and the original
  completed next-task observation under current owner authority.

The source task supplying experience is distinct from the later training
operation. Sharing evidence or computation does not erase that distinction.
Likewise, work payment does not guarantee model improvement. Both evaluator
NoUpdate and qualified-evaluation/no-admissible-proposal paths retain the whole
incumbent. Actual adoption still requires current original-owner authorization,
revocation, dependency and local-risk checks. Nodes may keep different valid
versions, and an experiment without benefit may end with NoUpdate.
