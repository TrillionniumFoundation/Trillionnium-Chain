# TRNM PoCO-BFT G1/G2 progress audit — 2026-08-27

This is a candidate progress audit, not a gate-promotion or production
readiness certificate.  It records the source seams, process probes, and
infrastructure observations completed in this run, together with the failed
or intentionally unrun checks.  `production_candidate` and
`production_consensus_activation` remain `false`.

## Authority and source binding

- Canonical worktree:
  `/home/alex/projects/worktrees/trillionnium-chain/poco-mainline-20260825`
- Branch: `docs/chain-poco-bft-mainline-20260825`
- Candidate source head: `db6092166` (`feat(poco-node): add candidate
  effect-driver process boundary`; the full object ID and tree are bound by
  `docs/development/plan-manifest-v1.toml` after this audit commit).
- Required preflight: `bash scripts/project-preflight.sh` passed before the
  source and documentation changes (`errors=0`).
- No remote push, system-service change, firewall change, package install, or
  persistent listener was performed.

## Source seams landed

| Seam | Commit | What is proven | What is deliberately not claimed |
| --- | --- | --- | --- |
| Core/SafetyRules authority | `7e66e66b0`, `b6488c083` | One non-cloneable Core-owned authority for Vote and Timeout; transactional Core/owner affinity; durable transition before Core install/signature release | Production constructor, finality, pacemaker, network, or independent crash closure |
| Bounded effect driver | `a852dba5b` | Generation-fenced bounded ingress; Safety persistence/readback; checkpoint CAS before signer; exact signed-outbound binding; fail-stop | Proposal/application/finality execution, recovery takeover, or production activation |
| Real OS process wrapper | `db6092166` | Feature-gated `trnm-poco-effect-driver-process`; line-delimited strict JSON; timeout path crosses the real driver and file-backed candidate hooks; black-box process tests | A validator node, network socket, arbitrary block path, or recovery owner |
| Authenticated nested wire corpus | `f898f1adf` | Independent RFC8032 Ed25519 reference verification; Vote/TimeoutVote/QC/TC nested signatures; 10,971 structural mutations and strict-prefix/crypto negatives | Live peer admission or network finality |
| Durable payload replay fence | `504e4aad0` (lint follow-up `2853cb481`) | Append-only hash-chain WAL, lease revalidation, namespace/session/generation/sequence binding, cross-process owner tests | Core-integrated production socket owner or whole-namespace anti-rollback |
| Fresh-genesis migration boundary | `5d3458e0e` | Typed one-way import; legacy WAL/key/data-directory and in-place reuse rejection; strict bounded decoder | Trusted Comet reader, independently recomputed target JMT, dual quorum, or cutover |

The source-level feature and package metadata keep all production and
activation flags false.  The new process is only compiled with the explicit
`g1-process-test-support` feature.

## Real process evidence

Command (run sequentially from `trillionnium/`):

```text
cargo test -p trnm-poco-node --features g1-process-test-support \
  --test effect_driver_process_e2e -- --nocapture
```

Result: **2 passed**.

The black-box trace uses a temporary absolute run root and the actual binary
over stdin/stdout.  A successful timeout produced:

```text
Safety transition WAL (durable) -> safety-state.record/readback
-> whole-node.checkpoint (CAS) -> Ed25519 signature -> outbound.wal
```

The machine response reported `processed_ingress=1`, `processed_effects=3`,
`broadcasts=1`, `candidate_only=true`, `finality_verified=false`, and
`production_activation=false`.  The test independently verifies the emitted
signature against the exact recorded signing root using the fixture public
key.

The same test also proves:

1. duplicate JSON keys are rejected before command dispatch;
2. an eighth queued command is admitted and the ninth receives typed
   `backpressure` without Core work;
3. an injected checkpoint CAS failure returns `fail_stopped`, leaves a durable
   Safety transition/state marker, and writes neither checkpoint nor outbound
   signature;
4. a non-empty candidate root cannot be reopened as fresh state and exits
   with `recovery_required`.

This is deliberately a fresh-state timeout slice.  It does not close G1-S01,
G1-S02, G1-S03, or G1-S06 because proposal/application/finality, both signing
purposes in one live node, physical power-loss, and a recovery owner are still
absent.

## Focused source gates

The following checks passed in the canonical worktree, run one at a time to
avoid Cargo-cache contention:

```text
cargo test -p trnm-consensus-core --lib                         # 230 passed
cargo test -p trnm-consensus-types --lib                        # 169 passed
cargo test -p trnm-consensus-crypto --test wire_authenticated_reference # 2 passed
cargo test -p trnm-consensus-types wire_semantic --lib           # 6 passed
cargo test -p trnm-consensus-peer-lease --lib --tests            # 10 + 2 + 2 passed
cargo test -p trnm-poco-node --features g1-process-test-support # feature suite passed
cargo test -p trnm-poco-lab-validator --test external_fenced_mesh -- --nocapture # 3 passed
cargo clippy -p trnm-consensus-core --lib --tests -- -D warnings
cargo clippy -p trnm-consensus-types --lib --tests -- -D warnings
cargo clippy -p trnm-consensus-peer-lease --lib --tests -- -D warnings
cargo clippy -p trnm-poco-node --features g1-process-test-support --lib --tests -- -D warnings
cargo fmt --all -- --check
```

The lab-validator crate still has a pre-existing whole-crate `-D warnings`
backlog (dead-code/large-enum and related diagnostics); its focused runtime
tests pass with ordinary warnings.  That backlog remains an explicit release
blocker and was not hidden by this audit.

The independent wire checker reports four valid frames, six named negatives,
3,609 strict-prefix mutations, and 44 crypto mutations.  The authenticated
vector SHA-256 is
`997a334e77901dd6507fcdf8061ec54ad318e2d5569ab0c9ebc662b42b60eefa`.

## LAN, macOS, and phone observations

The private read-only observation bundle is:

`/home/alex/.openclaw/workspace/artifacts/lan-node-matrix-20260827T010942Z/`

It contains `README.md`, host/toolchain/reachability/readiness JSON,
firewall observations, source hashes, and harness self-test output.  The
observation window was 09:09–09:20 CST.  It found:

- five validator-eligible Linux hosts (local, x230, desktop, ROG, j3160) and
  one macOS arm64 observer; ICMP was 5/5 and configured SSH was 5/5;
- direct LAN SSH was 4/5 because ROG refuses LAN port 22, while its Tailscale
  alias works;
- `probe_fleet.py --timeout-seconds 8` and
  `probe_run_readiness.py --timeout-seconds 8` passed 6/6; reserved PoCO
  listener count was zero;
- x230 and j3160 have UFW/input-drop policies, so currently unbound PoCO
  ports time out; no rule was changed;
- the desktop USB phone (`Trillionnium OS`, Android 16/sdk36/aarch64,
  ADB serial `ZY32JLVHGN`) received only the public authenticated wire vector.
  Its on-device SHA-256 matched the vector hash above.  No key, validator
  state, or service was sent to the phone;
- OpenClaw node pairing/service state was 0/0 and no node service was started.

The capacity evaluator accepts the declared 7/31/100 placements, but its
truth bits remain false.  It is infrastructure/readiness evidence only, not a
validator run.

## Failed or intentionally unrun external checks

The first actual `run_network_smoke_fleet.py` attempt was rejected because its
timeout was below the script minimum.  A retry at the minimum timeout failed
closed when the desktop SSH/hash command exceeded its bounded 30-second
window while that host reported a transient load average near 118.  The local
log is:

`/home/alex/.openclaw/workspace/artifacts/g3-network-smoke-20260827T021059Z.log`

No deployment evidence directory was accepted from that run; it is not
counted as a network result.  No firewall/service mutation was attempted to
make it pass.  The current fleet therefore has **no** signed validator run,
35-physical/42-logical P2P admission proof, fault/restart campaign, WAN
evidence, or performance evidence.

Earlier Linux reproducible builds (source before `db6092166`) were identical
across two independent v2 builds (`6a67cc...` validator and `5b6f94...`
material builder).  Raw macOS Cargo builds differed; the v2 macOS builder
then produced matching independent outputs (`0fab5c...` validator and
`ed53b8...` material builder).  Those artifacts are bound to the older source
and must be rebuilt against `db6092166` before any release claim.

## Remaining blockers and next executable queue

1. Bind the candidate process to proposal validation, native execution,
   application receipts, finality, and a real generation-aware pacemaker.
2. Add the Vote path to the same process owner and connect signer journal plus
   external monotonic watermark; retain mixed-cut and response-loss tests.
3. Implement an authenticated recovery owner (including whole-node
   anti-rollback) and run the physical power-loss/fault matrix.
4. Join the payload replay fence to a non-cloneable socket/peer owner and Core
   ingress, then rerun independent network replay on the LAN.
5. Implement trusted Comet finalized-state reading, target JMT writing, dual
   quorum, and fresh-genesis cutover rehearsal.
6. Rebuild the current source on Linux/macOS, deploy only ephemeral candidate
   binaries to the five Linux hosts, and retry the network runner once the
   desktop load and bounded SSH path are healthy.  The phone remains an
   observer for public vectors until a reviewed mobile harness exists.

None of these blockers is waived by this audit or by local infrastructure
reachability.  Production flags remain false until the signed G1/G2/G3/G4
exit evidence exists.
