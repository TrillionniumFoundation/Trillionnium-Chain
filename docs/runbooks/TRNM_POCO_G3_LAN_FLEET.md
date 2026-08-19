# TRNM PoCO G3 Stage0 LAN evidence runbook

Status: **contract/self-test only; no current readiness, build, validator,
multihost, fault, performance, geo-WAN, or production observation**

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

Until separate fresh evidence is produced and independently accepted, keep all
of these false: reproducible build execution; validator runs at every planned
size; signed multihost consensus; restart/fault completion; performance; LAN
multihost evidence; geo-WAN evidence; and production activation/candidacy.
