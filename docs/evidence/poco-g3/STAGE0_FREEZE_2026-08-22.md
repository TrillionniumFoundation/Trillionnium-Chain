# PoCO G3 Stage0 freeze ledger — 2026-08-22

This is a documentation-only freeze note for the current chain-consensus
worktree. It records the claim boundary; it does not create, upgrade, or
replace runtime evidence. A fresh read-only fleet/readiness observation was
added on 2026-08-23; it does not change any build, validator, multihost, or
production bit.

This note is an immutable dated snapshot of the 2026-08-22 boundary.  A later
2026-08-24 frozen-candidate observation is recorded under
`stage0-remap-observation-30c145ff6-20260824/` and is bound by the current
`status.toml`; its candidate-remap bit supersedes the snapshot's
`committed_candidate_rust_src_remap_fix_observed=false` line.  The only
remaining Stage0 observation blocker in the current ledger is
`validator_run_7_completed`; runtime, multihost, and production boundaries
remain unchanged.

## Assessed tree and savepoint lineage

The audit was run from the canonical linked worktree:

```text
root:   /home/alex/projects/worktrees/trillionnium-chain/poco-bft-v0-phase0
branch: feature/chain-poco-bft-v0
HEAD:   47a70581397dff47aeae118f6be4bf1baed4d6e6
status: clean after the current X230 evidence follow-up
tree:   1db3333a8b24b08b382fd726adc427b38b9842bd
```

The relevant committed lineage is:

```text
47a7058139  docs(evidence): bind current X230 reproducible build
└─ ac5880d2c9  ci(stage0): track current observation truth
   └─ 1808240d9  docs(evidence): bind current fleet readiness observation
      └─ af6c2737e1  docs(evidence): freeze Stage0 d0 claim boundary
         └─ d0c886c997  ci(stage0): register planned P2P admission contract
   └─ 6da6840380  test(stage0): define planned P2P connectivity admission
      └─ ffa2b8799a  fix(poco): bound fleet runtime control paths
         └─ 422654b0b6  evidence: bind Stage0 publication to held bytes
```

`6da6840380` adds a planned admission contract and fixture tests. `d0c886c997`
registers those tests in the local contract gates. Neither commit performs
network admission, copies a validator binary or secret, starts a validator,
or supplies a production authority.

`bash scripts/project-preflight.sh --audit` passed on this tree (with the
existing linked-worktree and `PROJECT_TOPIC` warnings). The original ledger
itself performed no SSH action. On 2026-08-23, the current read-only probes
were run separately through ordinary SSH on `p4-x230` and are recorded under
`current-observation-2026-08-23/`.

## The d6 record is historical and non-reusable

`docs/evidence/poco-g3/stage0-repro-d6bb34c1-20260820/` is an immutable,
historical observation for a different source candidate:

```text
source commit:       d6bb34c149edd07d6412b169c471dbb017eb301e
source Git tree:     d14ed7015b13f487738451e4243b8ec962db0f87
Cargo.lock:          50,286 bytes
Cargo.lock SHA-256:  3e2352127ef45a35f808a549cf459959b17054f615744382c0f00a3a6a29b6da
candidate tar SHA:   bf1f77a229d6eae8e975481728e157e87c6bb9e923ec0e3c2f8f422918e4ae58
evidence id:         trnm-poco-g3-stage0-linux-x86_64-repro-d6bb34c1-20260820
```

The current `HEAD` has a different Git tree and a different lockfile
(`trillionnium/Cargo.lock`: 50,318 bytes,
`72e254afa47d8b92fe8803b35869990bcfaa7f8106d9f0d4ecb45d127fbe150b`). The
historical d6 candidate also does not contain the committed rust-src remap
fix. Consequently, do not relabel, copy, or reuse its source archive,
`Cargo.lock`, tool hashes, build reports, or binary hashes as evidence for
`d0c886c997` (or any later savepoint). A new candidate and a new evidence ID
must be generated after the candidate commit is deliberately frozen.

The later committed-tool remap control is useful only as a scoped historical
control: it does not retroactively change the d6 candidate and does not
provide cryptographic runner attestation. A separate current-candidate X230
build record is now present under
`stage0-repro-ac5880d2-20260823/`; it binds the prior `ac5880d2c9` source
candidate and has passed deep source/report/ELF rehashing. It is explicitly a
prior-commit observation, not evidence for this later documentation commit.
The tracked v2 wrapper was also run on that candidate. Its report is preserved
beside the v1 records; v1 and v2 produced identical role hashes in this
environment, so no differential rust-src drift was observed and the typed
candidate-remap bit remains false.

## Current truth boundary

The release-relevant observation and runtime truth bits remain false. In
particular:

```text
stage0_observation_complete=false
committed_candidate_rust_src_remap_fix_observed=false  # 2026-08-22 snapshot
current_fleet_probe_observed=true
current_run_readiness_observed=true
stage0_deep_reverification_bundle_available=true
validator_runtime_started=false
validator_run_completed=false
validator_run_7_completed=false
signed_runtime_evidence_multihost_observed=false
multihost_consensus_observed=false
fault_restart_fleet_multihost_observed=false
fault_matrix_completed=false
performance_evidence=false
g3_lan_multihost_evidence=false
g3_geo_wan_evidence=false
production_activation=false
production_candidate=false
successful_process2_restart_observed=false
authenticated_process2_catchup_operational=false
recovery_ready_operational=false
recovery_start_operational=false
```

The 2026-08-22 snapshot's status checker reported the remaining Stage0
blockers as:

```text
committed_candidate_rust_src_remap_fix_observed
validator_run_7_completed
```

The current 2026-08-24 ledger has promoted the first bit from the new frozen
candidate record and therefore reports only `validator_run_7_completed`.

Contract/self-test positives are not observations. The local G3 contract gate
reports `cargo_executed=false`, `ssh_executed=false`,
`evidence_generated=false`, and `validator_run=false`. The planned P2P test is
fixture-only (`firewall_mutated=false`, `p2p_identity_authenticated=false`,
`validator_run=false`). The direct-seven test is also a bounded fixture and
reports no completed validator run. ParkedAck remains an inert handoff
savepoint, not a successful restart or RecoveryReady/RecoveryStart path.

## Preconditions for the next X230 campaign

Keep every false bit false until all of the following are satisfied and
accepted by the current checkers:

1. Choose and commit the candidate savepoint; verify the canonical root,
   chain-consensus lane, branch, and empty status with `project-preflight`.
2. Produce a fresh clean-commit source candidate for that exact commit. Bind
   its Git tree/blob/mode records, exact `Cargo.lock` bytes and SHA-256, source
   archive hash, and a new evidence ID. Never use the d6 directory as the
   current bundle.
3. Include the rust-src remap fix in the candidate/tool boundary and bind the
   tool source commit, wrapper/tool hashes, and complete transport bundle to
   the build reports. Re-run the deep byte rehash; do not rely on an
   invocation-local `reproducible_build=true` field.
4. Use a fresh X230 clone and the self-hosted runner only (no paid CI). Capture
   the runner/toolchain/cache facts and bundle fmt, check, and key-test logs;
   make the formal rerun offline after its cache is explicitly prepared.
5. Generate fresh fleet and run-readiness observations for this campaign.
   Historical 2026-08-13 JSON and contract fixtures cannot satisfy either
   acceptor.
6. Before copying any validator binary or secret, run a bounded, authenticated
   bidirectional P2P admission helper. Bind its plan/nonce, helper/tool hash,
   both-endpoint results, identity/authentication facts, and cleanup result to
   the prestart/direct-seven bundle. A fixture join is insufficient.
7. Only after those gates pass, run the real seven-validator campaign and
   collect signed runtime/finality/replay artifacts. Bind commit, lockfile,
   source archive, and binary hashes in the resulting evidence; then evaluate
   `check_stage0_observation_status.py --require-complete`.

Until that sequence completes, this savepoint is a clean contract/freeze
boundary only. It is not Stage0 complete, G3 LAN evidence, a restart proof, or
a production candidate.

## Fresh read-only observation (2026-08-23)

The current `probe-fleet-v1` and `run-readiness-v2` producers were run from
the canonical tree through `p4-x230`. Both current acceptors passed with six
hosts and zero probe failures. The exact raw reports are content-addressed in
`current-observation-2026-08-23/` and bound in `status.toml`:

```text
source commit:       af6c2737e1bf9d770076f8cb8b5a61887df619c7
source Git tree:     03bbc502b9fc716990806968f44da05805db6a39
Cargo.lock SHA-256:  72e254afa47d8b92fe8803b35869990bcfaa7f8106d9f0d4ecb45d127fbe150b
fleet report SHA-256: 1a4083c655298011b7d167bc9bf3127a3f1d5bba804566342966716bf0b7405d
readiness SHA-256:    be1e4041a0d7a760b8386204de948bb359410d0b5b83302d8931ac6471bc0be0
transport:            manual SSH via p4-x230
```

These are infrastructure observations only. They keep `build=false`,
`validator_run=false`, `multihost_run=false`, `geo_wan=false`, and
`production=false`; they do not satisfy the deep bundle, P2P admission, or
seven-validator requirements.
