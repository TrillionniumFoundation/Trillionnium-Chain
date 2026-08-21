# TRNM PoCO G3 Stage0 LAN evidence runbook

Status: **unsigned native build and X230 fresh-clone observations are tracked,
but rust-src cross-time drift disproves reproducibility for the committed
builder; a clean committed-tool v2 remap control kept v1 frozen and restored
native Linux cross-time reproducibility without placing the fix in
d6bb34c1/c971f1b0f; readiness, real validator runs, and production observations
remain false**

The tracked build-only observation is recorded in
`docs/evidence/poco-g3/stage0-repro-d6bb34c1-20260820/`. It covers two manual
SSH X230 builder invocations and two native macOS builder invocations for the
exact `d6bb34c1` candidate. It does not cryptographically attest runner
identity or execution, and it does not close Stage0.

The later
`stage0-repro-d6bb34c1-20260820/fresh-clone-gates-report.json` binds two
byte-identical clean clones, their empty statuses, the same commit/tree,
`Cargo.lock`, source archive, and transport bundle. Its first offline attempt
found the job-local Cargo cache incomplete, so public dependency fetch was used
before the formal offline rerun passed fmt, check, and the recorded key tests.
This is also an unsigned manual-SSH observation: its runner identity is not
cryptographically attested, its referenced logs are not bundled, and it did
not run a real 7-validator campaign.

The same candidate and rustc were later rebuilt on X230 after rust-src was
installed. Each pair of internal builds still matched and its schema-3 report
still said `reproducible_build=true`, but both binary hashes and sizes drifted
from the 2026-08-20 baseline because the physical rust-src sysroot path entered
`.rodata`. Treat `reproducible_build=true` as invocation-local identity only.

The final control cloned a complete tool bundle with `git clone --no-local`,
detached at exact clean commit `08efb8f4`, required empty status, and executed
the tracked v2 wrapper while keeping the evidence-bound v1 bytes frozen. V2
replaced only the native build seam, canonically remapped rust-src, and restored
both historical hashes in two independent builds. This supports native Linux
cross-time reproducibility through committed tool code. The unsigned manual-SSH
runner is not cryptographically attested, the bundle is recorded but unbundled,
the raw schema-3 report does not self-bind the tool hashes, and the fix remains
absent from d6bb34c1/c971f1b0f.

This runbook deliberately omits physical addresses, host identities,
management routes, and machine-local paths. Those belong only in the
authorized campaign inventory and fresh raw evidence. Shell variables below
must refer to newly created, non-overlapping locations outside the source
clones.

## 1. Freeze one clean committed source

Choose the exact commit only after all intended source is committed. Require
an empty `git status --porcelain=v2 -z --untracked-files=all`; a merely clean
index is insufficient. Record the commit ID independently, then create two
fresh clones and detach both at that exact object:

```bash
git clone --no-local "$REPOSITORY" "$FRESH_CLONE_A"
git clone --no-local "$REPOSITORY" "$FRESH_CLONE_B"
git -C "$FRESH_CLONE_A" checkout --detach "$CLEAN_COMMIT"
git -C "$FRESH_CLONE_B" checkout --detach "$CLEAN_COMMIT"
```

Neither clone may be edited. Candidate outputs must be outside both clones so
their statuses remain empty. Prepare independently with the strict profile:

```bash
python3 "$FRESH_CLONE_A/scripts/poco-fleet/prepare_source_candidate.py" \
  "$FRESH_CLONE_A" --output "$CANDIDATE_A" --require-clean

python3 "$FRESH_CLONE_B/scripts/poco-fleet/prepare_source_candidate.py" \
  "$FRESH_CLONE_B" --output "$CANDIDATE_B" --require-clean

cmp --silent "$CANDIDATE_A" "$CANDIDATE_B"

python3 "$FRESH_CLONE_A/scripts/poco-fleet/check_source_candidate.py" \
  "$CANDIDATE_A" --require-clean
python3 "$FRESH_CLONE_B/scripts/poco-fleet/check_source_candidate.py" \
  "$CANDIDATE_B" --require-clean
```

Any non-empty status, commit/tree change, differing tar byte, legacy profile,
or checker failure rejects the candidate. Do not select one of two unequal
archives by inspection.

## 2. Interpret the source bindings exactly

The `clean-commit-v1` inventory is schema 2 and binds all of the following:

- `base_commit` to the canonical commit payload;
- that commit payload's first tree header to `git_tree_oid`;
- every regular source path to its `git_blob_oid`, exact bytes, SHA-256, length,
  and `0644` or `0755` mode;
- the reconstructed flat inventory to the same Git tree OID;
- `git_status_sha256` to the SHA-256 of the empty status; and
- exactly one `trillionnium/Cargo.lock`, at mode `0644`, to its exact SHA-256
  and positive byte length.

In downstream schema-3 evidence, `source_tree_sha256` is the historical name
for the canonical candidate tar SHA-256. It is identical to the candidate
checker result `source_candidate_sha256`; it is **not** the Git tree. The Git
tree is `source_git_tree_oid`, interpreted using
`source_git_object_format`. Reviewers must compare both fields and must not
substitute one for the other.

## 3. Build twice on each native architecture

Use one of the byte-identical candidates. On each required native
architecture, invoke the builder from a clean checkout of the same tool
commit. Each invocation performs two independent locked/offline release builds
and compares the validator and material-builder bytes before emitting either
role:

```bash
python3 "$NATIVE_TOOL_ROOT/scripts/poco-fleet/build_reproducible_lab_candidate.py" \
  "$SOURCE_CANDIDATE" \
  --output-validator-binary "$NATIVE_VALIDATOR_BINARY" \
  --output-material-builder "$NATIVE_MATERIAL_BUILDER" \
  > "$NATIVE_BUILD_REPORT"
```

Run this once on native Linux/x86_64 and once on native macOS/arm64. Preserve
the separate binaries and stdout JSON report from each invocation. Both local
reports must be exact schema 3 and must carry the same clean-commit, Git tree,
empty-status, canonical-tar, and `Cargo.lock` bindings. A boundary self-test
whose output says `actual_build_executed=false` cannot fill either role.

Assemble the cross-architecture report only after both native builds exist:

```bash
python3 "$TOOL_ROOT/scripts/poco-fleet/assemble_reproducible_build_report.py" \
  "$SOURCE_CANDIDATE" \
  --linux-report "$LINUX_BUILD_REPORT" \
  --linux-binary "$LINUX_VALIDATOR_BINARY" \
  --linux-material-builder "$LINUX_MATERIAL_BUILDER" \
  --macos-report "$MACOS_BUILD_REPORT" \
  --macos-binary "$MACOS_VALIDATOR_BINARY" \
  --macos-material-builder "$MACOS_MATERIAL_BUILDER" \
  --output "$AGGREGATE_BUILD_REPORT"
```

The assembler rechecks the strict candidate, exact schema-3 reports, and all
four binary files, then emits an exact schema-3 aggregate. Downstream no-fault
assembly must propagate that schema-3 aggregate and an independently derived
schema-3 completed-run summary. Schema-2 build reports or summaries are not
current evidence and fail closed.

## 4. Produce fresh readiness evidence

The raw `lan-fleet-probe-2026-08-13.json` and
`lan-run-readiness-2026-08-13.json` files are preserved only as
historical/audit-only material. They are not inputs to the current gate, must
not be copied or renamed into a current campaign, and carry no present-tense
infrastructure claim.

Immediately before a formal campaign, produce fresh reports from the current
producers and pass the exact outputs to the current acceptors:

```bash
python3 scripts/poco-fleet/probe_fleet.py > "$FRESH_FLEET_REPORT"
python3 scripts/poco-fleet/check_baseline.py "$FRESH_FLEET_REPORT"

python3 scripts/poco-fleet/probe_run_readiness.py > "$FRESH_READINESS_REPORT"
python3 scripts/poco-fleet/check_run_readiness_evidence.py \
  "$FRESH_READINESS_REPORT"
```

`check_baseline.py` accepts only the current `probe-fleet-v1` shape.
`check_run_readiness_evidence.py` accepts only `run-readiness-v2`. Both reject
the historical filenames and legacy shapes. Their Python self-tests use local
fixtures and mutation controls; passing those tests is contract evidence, not
a fresh fleet or readiness observation. Do not set a readiness or run bit from
a self-test transcript.

## 5. Preserve the restart boundary

For the bounded direct-seven process-1 target, the operational durable suffix
is exactly:

```text
restart_prepare -> restart_cut -> restart_park -> restart_parked_ack
```

The handoff must retain and freshly revalidate the complete RestartCut,
RestartPark, and RestartParkedAck artifacts, the N/N ParkedAck admission-set
identity, the local ParkedAck statement, and the adjacent journal events. It
must also close the target's runtime-control server, pacemaker, and mesh and
leave no normal terminal report, metrics, final state, CleanStop, SafetyHalted,
or terminal archive seal.

Only that exact target process 1 may return status `75` with the exact schema-2
`process1-target-parked-ack-handoff` descriptor. Status 75 is a supervisor
handoff signal, not a completed validator report and not evidence of a
successful restart. Non-target validators must remain live through the
handoff.

The supervisor may then launch process 2 only with the exact process-1 command.
Process 2 independently reopens and authenticates the full
RestartCut/RestartPark/RestartParkedAck triple and replay boundary, but the
current path then exits at its exact authenticated inert stop. It still has no
authenticated start-catch-up activation, no operational RecoveryReady set or
RecoveryStart certificate transition, and no Core, signer, timer, mesh, or
ordinary-consensus activation authority. Typed structures and local tests do
not supply those missing operational joins. Therefore:

- the inert process-2 stop is not a passed `validator_process_kill` fault;
- status 75 plus a process-2 launch is not a successful restart;
- no restart/catch-up, validator-run, fault, performance, or G3 claim may move;
  and
- the fault/restart campaign remains plan-only until all missing authorities
  exist and a fresh external run is accepted.

## 6. Contract checks versus observations

The following tests are suitable lightweight contract checks. They do not run
a native release build or make a fleet observation:

```bash
python3 scripts/poco-fleet/check_source_candidate_test.py
python3 scripts/poco-fleet/build_reproducible_lab_candidate_test.py
python3 scripts/poco-fleet/assemble_reproducible_build_report_test.py
python3 scripts/poco-fleet/check_baseline_test.py
python3 scripts/poco-fleet/check_run_readiness_evidence_test.py
python3 scripts/poco-fleet/assemble_run_bundle_v1_test.py
python3 scripts/poco-fleet/collect_no_fault_run_bundle_v1_test.py
python3 scripts/poco-fleet/run_fault_restart_handoff_v1_test.py
```

The tracked unsigned observations make clean-clone fmt/check/key tests,
byte-identical source candidates, and invocation-local binary identity true for
the exact content-addressed `d6bb34c1` inputs. They do not make native
cross-time reproducibility true. The first offline cache was not ready; public
dependency fetch occurred; only the formal rerun was offline. The clean
committed v2 tool control keeps v1 frozen and makes the scoped native Linux
cross-time observation true. Until the fix is present in the exact source
candidate and fresh candidate-contained evidence is independently accepted,
keep all of these false: committed candidate remap fix; current
fleet/readiness; complete deep-reverification
bundle availability; real 7-, 31-, and 100-validator runs; signed multihost
consensus; restart/fault completion; performance; LAN multihost evidence;
geo-WAN evidence; and production activation/candidacy.

Print the typed observation status independently of the fixture/self-test gate:

```bash
python3 scripts/poco-fleet/check_stage0_observation_status.py
```

The default report is structured and currently says
`stage0_observation_complete=false`. Use `--require-complete` only where an
incomplete observation must make the command non-zero. Neither mode promotes a
contract/self-test transcript into an observation.
