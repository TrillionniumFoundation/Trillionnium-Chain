# Storage boundary follow-up

This continues the existing [sole plan](../../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md),
[model storage contract](../../../docs/development/specs/pon/CELL_MODEL_STORAGE_V1.md)
and [previous source-bound storage evidence](../README.md).
The delivered implementation closes four concrete boundary gaps across the
same eight-layer candidate. Funding, custody and actual-use authority retain
their existing owners. C/N validation and the D evidence checkpoint below are
historical snapshots; the later shared-source integration has its own scope.

## Latest publication composition

The [late integration record](late-publication-integration.json) preserves all
three new shared-branch commits through
`23a56123e3112de06d7c684ef2057578759176ff`, alongside the complete storage
G evidence checkpoint `d9681ca15570e71514b6445c190fa9fbdf50321f`.
The plan merges automatically; every non-plan input from both sides is preserved
before these explicit scope-documentation changes.

The new native change is a Node regression-test import: `sequence_root` comes
from its actual Node owner, while every test and assertion remains present. Its
exact corpus pin is updated. The M09 subtree and 43-case source-integrity suite
remain byte-identical to F, but the **whole native tree differs** and is now
`72c1c7ab529ef6b4df3bec5b45bbc9a3009755ff`. The late composition uses the
incoming `trillionnium`, `scripts`, `config`, `formal` and `.github` trees exactly.

All C/N/D/E/F execution records below retain their original commit identities.
No earlier native, Clippy or full source-gate result is renamed to this late
composition. Its exact clean head requires its own final static receipt;
combined-native, selected Node runtime and prospective-merge acceptance stay
**HOLD**. Production activation and CURRENT/FinalUse remain ungranted.

## What changed

1. **Require named tensor metadata objects.** A positional array such as
   `["F32", [2], [0, 8]]` no longer substitutes for the named safetensors
   object, even when the full container hash and independent tensor pins match.
   Reordered object fields remain legal; duplicate, unknown, missing and
   incorrectly typed fields still reject.
2. **Stop persistent intake when actual egress is spent.** New connections and
   frames stop after the actual response-byte limit is consumed. Temporary
   reservations remain refundable and do not impersonate permanently exhausted
   bytes. Already admitted workers retain their original deadlines and charges.
   Availability manifest reads now receive the original request deadline.
3. **Refuse known permanent contradictions before a new retained root is written.**
   Aligned capacity, immutable physical history, retired operation IDs and
   historical funding aliases are checked before creating a new catalog intent.
   This read-only precheck allocates nothing and does not replace the actual
   physical writer's audit. A genuine writer-lock failure still leaves a
   recoverable complete pending root. Historical impossible pending roots stay
   readable and protected; no migration or silent history deletion occurs.
4. **Carry Node's original storage deadline into the physical owner.** Already
   expired requests reject before new budget/physical obligations. The M09 writer
   uses that same deadline; uncertain committed outcomes retain the original
   charged claim/effect for same-ID reconciliation. Checks also cover completion,
   repair and retirement boundaries. M12's internal journal still has its
   existing cooperative intervals, including its SQLite busy timeout: this is
   not a hard wall-time limit on every M12 call.

## Exact sources

| Role | Commit | Tree |
| --- | --- | --- |
| R: old parser plus the exact regression test | `8992e87ab14d6905303b9a813656a591621a49bd` | `b0f6c1d4f57b9c434f01fcf983f1aa3abbc88530` |
| C: frozen storage implementation | `211e330fd1cfbdaf3e9ff552714df29c840ce675` | `a18dc9ffc20efe435ae8ebceecdca537b7013261` |
| N: published composition with migration/research | `568c97590eee9e95e6b5021a49fd0a5d20716fa7` | `ea600542130341144d697776d92048988d44572b` |

R and C derive from `a9b8602706b66adba82655c3c2ce90bde88620a2`.
N preserves the migration head `7a88207d` through intermediate `20cdab3b`,
then the research head `f8d65e96`. Its ordered parents are `f8d65e96` and
`20cdab3b`. The historical D checkpoint
(`dfbec36ca8126a8d388218c4fada512e1deabf71`) retained c57 and R as its
ordered parents. The test-only R/N merge comparison belongs to that historical
packaging step; it does not establish equality for later shared-source input.

[Complete composition checks](research-composition-preservation.json) passed
25/25 static conditions: 22 incoming paths and 12 implementation paths are
byte-exact, the plan contains both original insertions, and all **460 pins**
were checked by reading and rehashing 11,350,669 actual Git blob bytes. N's
whole Rust subtree equals `20cdab3b`; the M09 component and its direct workspace
dependencies equal C. These are source comparisons, not extra runtime tests.
The delivery also preserves the later `c57c2432` evidence update. Its
[34 static preservation checks](incoming-c57-preservation.json) confirm exactly
four changed historical evidence files, no pinned/native input change and
unchanged source trees. Those JSON/Markdown files remain inputs to the repository
structure checker. The c57 update and D checkpoint preserved N's native
source, Cargo graph, runtime readers and fixed test inputs. That equivalence
stops at D and does not apply to the subsequent shared-source integration.

## Recorded E/G shared-source integration scope

The [separate integration scope](final-integration-scope.json) combines D with
`d9954903ef9239f71aa575ec3e6f4fdaa88f2d35`, preserving its parent
`81da33e609cb64b319e8cfcca7059e5c30d39044`. The latter changes 26 native
paths, including Growth/W1/Node inputs and the Cell client's post-lock budget
check. All earlier server transport tests remain; seven transport tests are appended: four client tests and three server tests.
The [storage scope audit](incoming-81da-storage-scope.json) distinguishes those
new inputs from the C/N validation snapshot. No new native run is claimed here.

The [inventory successor](incoming-d995-inventory-scope.json) restores the
canonical generated `public_cli` inventory entry and its source pin. The incoming
whole native tree is `a706490dda20cb6093cc27ab3c59b1486aafb5b4`, which differs
from N/D. Its source corpus contains **464 pins**. The historical observation of
460 pins continues to belong to N/D and is not replaced with this later count.

[Preservation checks](final-integration-preservation.json) verify all 82 historical
non-plan paths and all 188 incoming non-plan paths before the explicit scope
edits, with both original plan insertions retained. At the E/F/G checkpoints, source subtrees
`trillionnium`, `scripts`, `config`, `formal` and `.github` equal the d995
incoming source. Only the plan and this evidence package add the storage delivery record.
[Source-guard review](incoming-81da-sourceguard-scope.json) identifies 43 tests,
up from 34; the other 72 controls are unchanged. A planned 43-test invocation is
not an executed 115-test run. Fresh execution must use an exact clean commit in
`head` mode and its original before/after source recorder.

C's native passes and N's controls/Clippy retain their original source identities;
they do not qualify the new combined native tree. D's completed
[source-check receipt](delivery-checkpoint/delivery-source-checks.json) and
[log](delivery-checkpoint/delivery-source-checks.log) are also preserved as D-only
observations. They add formatting, inventory, 460-pin, CI-contract, 2,688-link
repository and [Cargo-graph](delivery-checkpoint/cargo-metadata.json.gz) checks;
that invocation ran no Python control tests or native tests. Combined native,
all-feature, Node runtime and prospective-merge acceptance remain **HOLD**.

## Exact integration check and retained repair observation

The first exact-commit integration run on
`b72d44476a12ed1b0dbf0891556adf280eba661b` completed **43 source-integrity
tests**, formatting, generated inventory, **464 exact pins** and CI-contract
checks. The [original receipt](integration-e/final-integration-source-checks.json),
[raw log](integration-e/final-integration-source-checks.log) and
[step results](integration-e/result.json) preserve the overall **exit 2**:
the repository checker found the incoming W1 README's missing
`lifecycle21-direct.log`. Cargo metadata was not reached after that failure.
The `FAIL` lines produced by rejection fixtures are expected output inside the
43 passing controls; they are not independent acceptance results.

The earlier [wrapper invocation](integration-e/wrapper-invocation.json) stopped
with exit 126 before entering the recorder. Running the byte-identical shell
script through `bash` corrected its invocation without changing source, runtime
profiles, permissions, selectors or acceptance conditions. These observations
are retained separately; a repaired successor requires a fresh exact-source run.

The [evidence recovery](w1-evidence-recovery.json) restores the linked lifecycle
log and six additional original logs whose digests were already declared by
committed W1 metadata. All seven files match those existing hashes; the original
metadata and links remain unchanged. The interrupted build remains unsuccessful
with an unknown exit code. The lifecycle metadata lacks an execution commit/tree,
so neither its introduction commit nor this recovery is relabelled as a new
exact-source execution. Unbound extra logs are not assigned acceptance results.

## Completed repaired integration validation

The repaired F checkpoint `d6be11987b44deb0028382bd9f791dc1c4efc37f`
(tree `4604138f131fed7a68e417c9c3e1a5f074638c23`) completed the unchanged
full source-check command with **exit 0**. Its [exact before/after receipt](integration-f/final-integration-repair-source-checks.json),
[raw log](integration-f/final-integration-repair-source-checks.log),
[step results](integration-f/result.json) and
[complete locked Cargo metadata](integration-f/cargo-metadata.json.gz) are retained.

The actual result is **43 source-integrity tests passed**, formatting and generated
inventory passed, **464 exact source pins** checked, CI contract passed and
**2,785 local links** validated across 1,135 Rust files and 26 workspace packages.
The locked/offline Cargo graph contains 175 resolved packages; Cargo.lock remains
unchanged. All 9,305 tracked entries / 950,106,147 bytes matched the same F
identity before and after execution. Repeating the earlier 43 controls adds no
new unique test identities. Neither native tests nor Clippy ran in this command.

The [delivery-input projection](final-delivery-input-projection.json) binds the
G evidence-only checkpoint to F's unchanged source inputs. It does not
transfer C's native tests or N's Clippy to the new combined native tree. The
original Node build-resource failure, failed E repository check and interrupted
runs remain intact. Combined native and activation acceptance remain **HOLD**.

## Actual validation

[Artifact hashes](artifact-manifest.json) cover the retained files; the
[historical D source projection](delivery-source-projection.json) records D's
comparison with N; it is not an equivalence certificate for the later integration.
The unchanged [C/N structured snapshot](delivery-results.json) retains the exact commands, source
identities, counts, log digests and limitations. Every completed recorder below
verified the full tracked bytes before and after its command and found equal
source identities.

| Tested source | Scope | Actual result |
| --- | --- | --- |
| C | M09 library | **295 passed / 0 failed / 0 ignored** |
| C | CLI integration | **29 passed / 0 failed / 0 ignored** |
| C | Compile-fail documentation | **8 passed / 0 failed / 0 ignored** |
| C | Python controls | **106 distinct passed**: 34 + 35 + 22 + 11 + 4 |
| N | Python controls and source checks | **106 distinct passed**; formatting, inventory, 460 source pins, CI contract and repository checks passed |
| N | Whole workspace / all targets strict Clippy | **PASS**, `-D warnings`, locked/offline, default features and original dev profile |
| N | Selected Node storage/Legacy tests | **NOT_RUN**: compilation failed with `No space left on device`, exit 101; **0 test harnesses / 0 tests executed** |

The C [native receipt](final/storage-native.json) and
[raw log](final/storage-native.log), C [source receipt](final/storage-source-controls-corrected.json),
N [source receipt](composed-final/composed-source-controls.json) and
N [Clippy receipt](composed-final/composed-workspace-clippy.json) provide the
completed observations. The qualified [Node attempt](composed-final/composed-node-selected-qualified.json) and [raw compiler log](composed-final/composed-node-selected-qualified.log) retain the resource failure; its source checks completed but no selected test ran.

The separate [four-case oracle run](final/model-root-oracle.json) repeats the
same four identities and adds no unique coverage. Two zero-test binary harnesses
also add none. [Retained-test coverage](final/retained-test-coverage.json)
checks every original 186 library name, every historical 281-name set and all
288 a9 names against the completed 295-name run. This round adds **7** M09
tests: archive 4, persistent transport 2 and tensor 1. The other seven added
since the historical 281 already existed in a9. Process-child output is not
counted twice. The M09 command used `--tests` and `--doc`; it does not claim
execution of example test targets.

Both complete Cargo metadata snapshots resolve 26 workspace members and
175 packages; Cargo.lock contains 180 package entries. The unchanged lockfile
SHA256 is `00f3573879f3da7d5a702a8bc13245196bbfd53b86b0b6eb19c51f14887cef61`.
The complete compressed JSON is retained for [C](final/cargo-metadata.json.gz)
and [N](composed-final/cargo-metadata.json.gz).

## Preserved counterexample, failed invocations and interruptions

- **R executed one actual failing test**, 0 passed / 1 failed / exit 101:
  `cell::tensor_tests::tensor_entry_sequence_cannot_replace_required_named_object`.
  Its [receipt](red/tensor-old-parser-red.json) and
  [raw log](red/tensor-old-parser-red.log) retain the old parser's acceptance of
  a correctly hashed hostile container. R changes only the test file; the
  parser equals a9 and the test bytes equal C. The identical test passes on C.
  F32/F16/BF16 are subcases of one test.
- The first [C source-control invocation](final/storage-source-controls.json)
  exited 5 because an incorrect oracle filename selected zero tests. The
  corrected selector `test_model_release_root.py` completed successfully.
  The failed zero-selector result is not counted as a pass.
- The first [Node baseline](baseline/baseline-node-composition.json) used an
  unqualified loader environment and was interrupted, tool exit 130 and zero
  tests. Its original running/null receipt is preserved with the separate
  [interruption record](baseline/initial-runtime-interruption.json).
- A later environment transport failure interrupted C's workspace Clippy and
  intermediate M's source revalidation. Both original receipts remain
  running/null, with no complete before/after pair. The
  [environment interruption](environment-interruption.json) records unknown
  exit codes and no PASS; successful later N runs do not rewrite those attempts.
- The first N Node attempt replayed the initial test-profile SQLite boundary's
  stale unqualified build-script output. The exact
  [cache diagnosis](runtime-cache-diagnosis.json) preserves eight original
  output/fingerprint files and proves the library depended on the old failed
  result. Its [interruption](node-unqualified-cache-interruption.json) records
  exit 130 and **zero executed tests**. The same corrected Rustup launcher was
  retained. A package-only [clean](runtime-package-clean.json) removed 61
  rebuildable files / 28.9 MiB from this task's target; no source, qualification
  guard, profile, selector or deadline changed. The [fresh build result](runtime-cache-requalification.json) passed the unchanged original qualification guard and the current SQLite library bound that new result. The subsequent original Node test-profile build then failed with ENOSPC before any test executed. The actual compiler command retained `opt-level=3`, `debuginfo=2` and debug assertions.

After the ENOSPC failure also prevented saving the final summary, a
[completed-target cleanup](completed-owned-target-cleanup.json) removed 4,009
rebuildable files / 1.0 GiB from this task's target. Sources and all logs were
retained. Resource snapshots and owned-cache cleanup are observations of this shared
execution environment, not performance benchmarks or a causal OOM diagnosis.
The preserved diagnostic receipts explain incomplete work; they do not grant
native I/O, full Node, public network or release qualification.

The earlier [worktree-cleanup observation](completed-validation-worktree-cleanup.json)
claimed physical removal. A [later correction](completed-validation-checkout-removal-correction.json)
found an unregistered A9 checkout still present and verified all 9,023 tracked
files before a partial removal encountered changing directory contents. Further
removal stopped. The [exact-duplicate cleanup](final-owned-historical-dedup.json)
then shared 147 byte-identical historical evidence files only within this task's
own directories. No source bytes, logs, Git history or other workspaces changed.
[Incoming materialization](incoming-source-materialization.json) separately records
failed fetch/encoding/resource attempts and exact Git-hash-verified recovery;
none of these operations is a native test.

## Eight-layer status


| Layer | Implemented candidate scope | Remaining actual gate or profile boundary |
| --- | --- | --- |
| Objects | Canonical, versioned manifest/hash domains; complete payload hashes; bounded TMT1/TMA1 dense tensor validation. This follow-up requires named tensor objects and preserves strict field checks. | Supported tensor types are F32/F16/BF16. Other codecs, quantization, architecture and model quality need explicit admission. |
| Deduplication | Raw chunk CAS, TCX1 exact chunk reuse and shared original manifest duties support incremental byte publication. | Semantic adapter rebasing and an Expert ABI are absent. Changed contexts can reuse equal raw chunks but do not establish shared physical obligations. |
| Dependencies | TCD1 checks the complete declared graph; TMR1 binds router and direct-parent metadata; loader context is independently pinned. | The release owner must enumerate every real dependency. Bytes cannot reveal an omitted external requirement. |
| Transfer | Bounded sources, verified-prefix resume, observed-rarity scheduling and explicit persistent reuse retain aggregate budgets. Actual egress exhaustion stops new intake; temporary reservations can be refunded. | WAN fairness, confidentiality and performance require deployment evidence. Blocking I/O remains cooperative. |
| Discovery | Signed rendezvous hints retain TTL, replay, query-budget and observed source/prefix-diversity checks. | No DHT implementation or proof of eclipse/Sybil resistance, endpoint control or operator independence is established. |
| Retention | TCA2 binds complete roots, immutable funding/operation identities, terms and repair deadlines. New permanently impossible reservations reject before intent publication; old pending history remains protected. | Replica declarations need independent complete-copy evidence. Funding, lease extension, current height and successor authority remain separate owners; automatic funded renewal and erasure coding are absent. |
| Collection | Pending, acknowledged and expired-but-unretired roots protect all members; unsettled repairs block physical retirement. | Explicit retirement still needs the original owner conditions. Cache eviction neither releases paid duties nor proves filesystem blocks were freed. |
| Use | Fresh closure/payload and declared tensor checks precede exact create-only TMA1 completion publication. | Actual selected-runtime compatibility, CURRENT/withdrawal, resource admission and FinalUse must still succeed at use time. |

Node source now carries the original deadline into M09 physical reservation and
checks owner boundaries around completion. Unknown committed outcomes keep the
same charged claim/effect and permit reconciliation without redispatch. The recorded
selected Node attempt on N is **NOT_RUN** because the qualified test binary could
not be built within available disk space. M12's existing journal intervals
remain cooperative; this follow-up does not impose a hard deadline on every
internal M12 SQLite wait.

## Reproduction and remaining acceptance

The actual [runtime wrapper](qualified-runtime.sh) records Rust 1.95.0, the
original profiles, one Cargo build worker, disabled incremental compilation,
one test thread and the observed OpenSSL 3.5.9 provider identity. Its absolute
paths are an execution snapshot; use a matching checked-out source and runtime
installation when reproducing. Commands and full arguments are in each receipt.
The [original Node selector list](run-node-selected.sh) contains all 12 exact
names; the final runner changes only log destinations. Never overwrite a prior
failed/incomplete record to present a new result as its replacement.

[Publication readback](published-N-readback.json) confirms N reached draft
PR #688 by expected-head, non-forced update. It also records the actually created
original-workspace and required-baseline CI runs as pending at observation time.
No remote success or prospective-merge acceptance is inferred, and the local
work does not wait for those jobs.

Complete original-workspace/all-feature and platform execution, actual
model/loader compatibility with CURRENT/withdrawal/FinalUse, funded renewal,
independent complete-copy or specified erasure-code evidence and the original
independently operated WAN repair/loss/eclipse/hot-model campaigns remain
separate requirements. Expert/quantized/erasure-coded extensions need explicit
profiles and their own tests. Production activation, public-WAN acceptance,
independent acceptance, automatic funded renewal, new Expert ABI acceptance,
whole-chain quantum-security qualification and CURRENT/FinalUse grants remain
false.
