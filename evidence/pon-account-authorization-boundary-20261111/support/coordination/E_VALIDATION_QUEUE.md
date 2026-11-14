# Prepared validation queue for the evidence-only child E

Status: **prepared, not executed**. No Cargo, remote command, commit, staging,
or repository mutation was performed to prepare this queue. E does not yet have
an assigned SHA in these files. The generator requires the actual complete new
commit SHA and the already reviewed assembly payload/manifest hashes; it never discovers
an expected commit by reading `HEAD`.

## Scope and ordering

The frozen parent is `cdd984808a088e6c2e13b1e1ae6630a94d500c89` (Z), tree
`1ed39b6ebe55cb00c238f26f6bfc9361ab93faec`. E must be a direct, single-parent
child of Z. Its only additions may be under
`evidence/pon-account-authorization-boundary-20261111/`. Every previously
tracked path, mode, type, and Git object must remain identical.

Do not update the desktop checkout from Z, reuse its Cargo target for E, or
start this desktop queue until the original `/data` Z job has reached its
actual terminal outcome and that outcome has been retained. That job's final
source guard must observe the source it actually tested. Preparation here does
not authorize relabeling a running Z observation as E.

`AGENTS.md` preflight remains required before the eventual edit/commit/import
operations. These queues also run the original preflight before validation.
Both hosts run a complete raw-byte source guard before and after their checks;
the original recorder's clean-Git checks do not replace those raw guards.

## Prepared files

- `prepare_evidence_child_validation.py` only reads pinned historical contexts
  and prepares new queue JSON, launch scripts, a proof-helper copy, and command
  provenance in a fresh directory under `coordination`. It does not launch Git,
  tests, the recorders, or any remote action.
- `verify_evidence_only_child.py` is a read-only checker for later execution
  under the original recorder. It proves the exact Z-to-E relation and checks
  the entire reviewed evidence payload, including the preserved full-Rust FAIL
  and original Node INCOMPLETE record.
- Generated `run-local-queue.py` and `run-desktop-queue.py` contain E as a literal
  40-character SHA in every relevant argv. They call the existing recorder once
  for each command. They refuse pre-existing receipt directories and do not
  retry, overwrite, change flags, or synthesize a terminal result.

When both identities exist, the root can prepare concrete files with:

```text
python3 /workspace/scratch/a4188f5c86b5/coordination/prepare_evidence_child_validation.py
  --head <actual-full-E-SHA>
  --expected-payload-sha256 <reviewed-helper-payload-SHA256>
  --expected-manifest-sha256 <reviewed-final-manifest-SHA256>
  --output-dir /workspace/scratch/a4188f5c86b5/coordination/e-validation-<actual-full-E-SHA>
```

The placeholders above are explanatory and not runnable values. The parser
rejects abbreviations, refs, and Z itself. Use the `payload_sha256` from the
reviewed assembly inspection, also stored as `reviewed_payload_sha256` in the
delivery manifest; do not substitute the archive hash, manifest hash, or E tree
hash. Review the generated literal queues and their output hashes before use.
The separately pinned manifest hash also binds the generated record/binary
indexes, which are deliberately excluded from the assembly payload digest.

Generation produces six files: local/desktop queue JSON, local/desktop launch
scripts, the exact proof-helper copy, and a provenance JSON. No new validation
result is created by generation. The provenance gives the two exact files to
copy to the already authorized desktop records directory for later execution.

## Local queue: 13 independent command receipts

The existing local recorder is
`/workspace/scratch/a4188f5c86b5/coordination/run_validation.py`. It places fresh
receipts under `validation/<literal-E>/<id>/` and uses the original Rust 1.95.0,
five pinned PQ-provider files, jobs=1, unchanged build flags and the existing
`target-pq-profile-boundary-local` cache. The same-filesystem `validation-tmp`
setting remains unchanged.

| Order / receipt ID | Actual command or exact scope |
| --- | --- |
| 1. `e-preflight` | `bash scripts/project-preflight.sh` |
| 2. `e-source-before` | Original `verify_ci_source.py --kind head --expected-head E`; full tracked bytes, modes, source identity and untracked/index checks. The argv stores literal E. |
| 3. `e-evidence-only-relation` | Prepared read-only checker: direct Z parent; every old tracked object/mode/type; exact allowed evidence addition; unchanged top-level trees; pinned payload manifest and raw bytes; original recorder/environment hashes. |
| 4. `e-workspace-graph` | `cargo metadata --locked --offline --all-features --manifest-path trillionnium/Cargo.toml --format-version 1` |
| 5. `e-fuzz-graph` | Original `env CARGO_HOME=/workspace/scratch/a4188f5c86b5/fuzz-cargo-home cargo metadata --locked --offline --manifest-path tests/fuzz/Cargo.toml --format-version 1` |
| 6. `e-format` | `cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check` |
| 7. `e-repository-source-contract` | `python3 scripts/ci/check_repository.py`: all Markdown links, JSON/TOML parsing, source/ownership inventory, claim flags and CI contract source validation. |
| 8. `e-pq-integration-check` | `python3 scripts/ci/check_pq_research_integration.py` |
| 9. `e-pq-integration-tests` | `python3 scripts/ci/test_pq_research_integration.py`; original 59 integration tests, including positive and negative controls. |
| 10. `e-ci-source-integrity-tests` | `python3 scripts/ci/test_ci_source_integrity.py`; original 43 positive and negative controls. |
| 11. `e-w1-fixed-fixture-tests` | `python3 scripts/ci/test_w1_lifetime_ledger.py`; original 19 tests, historical golden pin and independently fixed successor fixture unchanged. |
| 12. `e-m06-retained-tests` | `cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-mvcc-fee --all-features --tests -- --test-threads=1` |
| 13. `e-source-after` | Original full raw-byte source guard for literal E, attempted in the launcher's `finally` block. |

The M06 prior Z observation was 18 test executables/suites, 272 passed and nine
ignored, with zero failed/filtered tests. This includes the five new M06
controls. It is an expected retained roster for review, not a pre-filled E
result. The E invocation must actually execute and retain its real counts;
ignored tests stay ignored. `--tests` does not claim example or doctest coverage.

The W1 tests read fixed source pins and actual prior Git objects; they do not
derive a new expected golden from E. Both historical and successor reports
must remain byte-identical to Z. No acceptance flag or numerical claim is
rewritten for this queue.

## Desktop queue: six independent command receipts

The existing desktop recorder is
`/home/qian-qi/chain-pq-a418-final-records/run_validation.py`, invoked through
the actually used `/usr/bin/python3`. It writes fresh records beneath
`/home/qian-qi/chain-pq-a418-final-records/validation/<literal-E>/`.

The first three commands are the same preflight, complete E source guard, and
evidence-only relation checker described above. The next two are:

| Receipt ID | Native command after the original environment prefix |
| --- | --- |
| `e-node-new-tests` | `cargo test --locked --offline --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib store::account_profile_scope_tests:: -- --test-threads=1` |
| `e-strict-workspace-clippy` | `cargo clippy --locked --offline --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features -- -D warnings` |

The sixth command is the original complete `e-source-after` guard. Both native
commands retain this exact prefix from the real `/data` retry's observed argv:

```text
env
  CARGO_HOME=/home/qian-qi/chain-pq-a418-final-cargo-home
  TRNM_CI_TOOL_ROOT=/home/qian-qi/chain-pq-a418-final-ci-tools
  CARGO_TARGET_DIR=/data/chain-pq-a418-node-retained-target-20261111
```

The prefix belongs inside the recorder's `--` command argument. Setting only
the launcher's environment would be ineffective: the original recorder
applies its recorded base environment before starting the actual command.
All other toolchain/provider variables and flags come from the original
desktop environment report, with Rust 1.95.0 and the five provider byte pins.
The generated launcher refuses a missing selected target instead of silently
creating a new target or changing optimization settings.

The Node prior Z filter executed four tests, with 1,398 filtered and none
ignored. Those figures are explicitly labeled as prior observations in the
queue. They cannot be counted as E passes until the E command actually runs.
The focused Node command does not replace the retained Node package, doctests,
ignored release controls, or original full-lane oracle consumers.

## Exact source and payload proof

The proof checker uses `git --no-replace-objects`, with lazy fetching disabled.
It compares the complete recursive Z/E trees, including file modes, object
types and object IDs. All old tracked paths must exist unchanged; all added
tracked paths must be regular blobs under the one allowed evidence directory.
It separately records unchanged tree IDs for `trillionnium`, `config`,
`scripts`, `.github`, `tests`, and `docs`, and checks every old top-level object
outside `evidence`. Existing contents of `evidence` remain unchanged through
the recursive comparison.

It then verifies every manifest member's current length/hash, the manifest
sidecar, exact reviewed manifest bytes, tracked-member coverage, derived-index hashes, and the reviewed
assembly payload SHA using the same canonical payload definition as the
assembler. The manifest and record index remain bound to their historical Z
observation cohort, even though this verification command itself runs on E.

The original desktop full-Rust record must still be `FAIL`, rc101. The original
Node all-targets record must remain `INCOMPLETE_EMPTY_RESULT` with no terminal
pass, return code, completion time or execution-after source claim. New E tests
cannot amend these records. The proof also requires all qualification flags to
remain false and does not assert equality of runtime binaries merely because
tracked runtime/build files have unchanged Git objects.

## Failure handling and honest coverage

Preflight, the initial full source guard and the exact relation/payload proof
are preconditions. A failed or incomplete precondition stops subsequent body
commands; the final full guard is still attempted. A normal body check failure
is preserved while other independent checks may continue. Existing record
directories are never overwritten, no automatic rerun is performed, and a
missing/empty/malformed result remains an incomplete/unavailable receipt in
the launcher summary. Wrapper return codes are reported separately from an
actual retained command result.

AGENTS has no evidence-only waiver. This queue performs its named exact-E
graph, formatting, strict Clippy, source-integrity, links and M06 retained-test
checks, plus focused Node boundary tests. It does not claim all retained
workspace/Node tests or hosted CI requirements are satisfied. The broader
required `repository-truth`, `protocol-contract`, `fuzz-smoke`, `rust-baseline`
and `external-evidence-contract` checks remain the existing requirements.

No full global lane is queued again merely to seek a green result. The original
Z full Rust failure, original Node incomplete attempt and every earlier failed
observation remain visible. Hosted runtime/quality shards and their current
run/attempt fan-in, prospective-merge checks, four explicit release controls,
and unexecuted oracle/doc-test scopes are not certified by these local/desktop
commands. Every generated queue and launcher summary keeps full CI and
production acceptance false.
