# G1-R3 ordinary Proposal authority gap ledger v1

Status: **BLOCKED_UPSTREAM** (candidate-only; not a Gate or release claim)

Package: `G1_R3_ORDINARY_PROPOSAL_AUTHORITY_V1`
Agent: `A03`
Gate: `G1`
Repository: `TrillionniumFoundation/Trillionnium-Chain`

This ledger is bound to the exact candidate source observed for this run. It
does not promote a machine flag, activate a production route, or replace the
canonical Plan/evidence/release truth.

## Source and authority tuple

| Item | Exact value |
| --- | --- |
| candidate ref | `refs/heads/feature/chain-g1-r4c-full-gap-closure-20260829` |
| candidate commit (base) | `6e0189e351015ef3230f217ca7ff86149baedcf0` |
| candidate tree (base) | `efea864cb2fbc4835a59a089b3dbab8934e71231` |
| assessed Plan ref | `refs/heads/docs/chain-poco-bft-mainline-20260825` |
| assessed Plan commit/tree | `8198fea0307eb368df34ff77ffc272a6b0e655ec` / `a1be71bba1b54c428493d186fafb656d081b31a9` |
| canonical Plan ref tip observed | `92449b8e101642f39d644d863db7bb60dea488f7` / tree `cf8f1ab4f5065cb0551a30ec0e036cd44cb31766` (newer; not silently substituted for the assessed source) |
| machine truth | `config/consensus-mainline.json` SHA-256 `19baef8a393d235b4f87a1351e2b8cdf2e7bb1f2eea8770ecc67d3e18966c6be` |
| release truth | `RELEASE_READINESS.md` SHA-256 `1659693f0662f8a19b526c602379fe9fa54626afefe33d35917983f699f2dfa4` |
| governance source (assessed docs snapshot) | agent-fleet PR #8, `a3bdc659d42b92574e591ab687d92a6672ec7cc0`, tree `c36032581897d86f2f6b8d295af2b685622f8f90` (read-only; not merged) |
| governance source (current PR-head revalidation) | PR #8 head `8bfd73f0cf1b785a29ae212f13212e51fe34231e`, tree `cfedd363147934f50d1352dae31b7d87d79aa8d9`; control/registry bytes match the previously read current governance files |
| control contract SHA-256 | `54cd6d8233ff7812427cf2b8e208ba7628f0593cbfc1b5db545f29b4d3c86d2e` |
| agent registry SHA-256 (assessed snapshot) | `c43a8470def968f78676787b1220b1f9a1d5faa53ec93137f73a9a71fbeb43a8` |
| agent registry SHA-256 (current PR-head) | `cafffe3c45c32a838485a4e6502ccb25b5a5a15245a6d6893f981905ff8d24a3` |
| scope | A03 ordinary validation, native P host, proposal-side driver hook, R3 tests/docs |
| authority | candidate; Core-owned capabilities remain opaque and non-cloneable |
| classification | `candidate-non-normative` |

## Remote dependency revalidation

These are read-only observations from the final fetch for this run. They are
not accepted interfaces and do not alter the assessed Plan source.

| ref | commit | tree | relevance |
| --- | --- | --- | --- |
| `refs/heads/main` | `b2d485e5641614ea0ca34ebf80a5f7843ff1e6d9` | `ffbad926850a12159336126390271abffc1d99a6` | repository main; no package authority |
| `refs/heads/docs/chain-poco-bft-mainline-20260825` (current tip) | `92449b8e101642f39d644d863db7bb60dea488f7` | `cf8f1ab4f5065cb0551a30ec0e036cd44cb31766` | newer than the separately assessed Plan snapshot; not substituted |
| `refs/pull/2/head` | `0db883131f28f25faf3d2a9e684b997e7aa9909d` | `2d727577bde41d5b9c3c294212e8e9682a5ead15` | A02 Draft; replay/body owner; no accepted handoff |
| `refs/pull/3/head` | `fda42ca060ebd00724cf644a96e7e1fa6b108ae2` | `3e8905237a57bee9db2a4b5ccee417f1eff0490b` | A02 Draft; replay-to-Core coordinator; no accepted handoff |
| `refs/pull/8/head` | `8bfd73f0cf1b785a29ae212f13212e51fe34231e` | `cfedd363147934f50d1352dae31b7d87d79aa8d9` | governance/CI Draft; control hash unchanged; registry ownership boundary updated |
| `refs/pull/9/head` | `97a96c01d8e85a189b3fc65650907f3159700515` | `3bd490ef4f6cfc96aea44a20b3f1d2f35f70d642` | A04 Draft; native-application/finality only; no R3-owned edits |

No open branch or PR was found for A03/R3 ordinary proposal authority. PR #2
and PR #3 remain Draft with commented (not accepted) reviews and no owner
interface digest; PR #9 remains an A04 Draft. The candidate base remains the
exact tuple above, so no `BASE_DRIFT` was emitted.

## Gap rows

| ID | Severity | Owner/dependency | Status and evidence | Deterministic next action |
| --- | --- | --- | --- | --- |
| `R3-TRI-001` | P1 | A03 | **Closed locally (candidate)**. `CandidateOrdinaryValidationOutcomeV1` now carries Core-facing `Sealed`, `Unavailable`, and `DeterministicallyInvalid` states plus an explicit `Unsupported` capability marker. The driver sends the two negative states to Core as typed `PayloadValidated` inputs and clears the retained proposal before the callback. Focused negative tests were added; execution is not yet verified because this clone has no Cargo/Rust toolchain. | Run the focused library tests and inspect Core safety-completion facts in an authorized Rust environment. |
| `R3-BODY-001` | P0 | A03 with A02 handoff | **Open.** The process hook still decodes the opaque fixture `candidate-synced-proposal-v1` and derives synthetic receipts; it does not retrieve a complete authenticated body/evidence bundle. | Consume the accepted A02 resolution interface in the process adapter; keep the fixture path fail-closed. |
| `R3-MAP-004` | P0 | A03/native execution | **Partially mitigated; open.** `CompleteNativeExecutionFailureV0` now preserves runtime-attempt outcomes: state-read failure reaches `Unavailable`, transaction-reject disposition reaches `DeterministicallyInvalid`, runtime invariant disposition reaches `CorruptStore`, and an unknown runtime disposition is fenced as `CorruptStore`. Other unknown complete-execution errors still use the legacy invalid fallback; `CompleteOverlayView` currently erases corruption-vs-I/O detail, and `trnm-native-execution-v0/src/lib.rs` legacy execution, preview, H1 state-sync, and other wrappers remain unclassified. No Rust tests ran in this clone. | Introduce an exhaustive typed complete-execution error boundary (including store/JMT/profile/commit ambiguity), add state-read/invariant mutants, and update every entry point before treating mapping as closed. |
| `R3-CONTEXT-001` | P0 | A03/Core upstream | **Blocked upstream.** The ordinary process Core starts with a header-less trusted-genesis parent, while the native P host requires an authenticated application parent/JMT head. Validator-set, parameter, and runtime-profile binding is not available at the process boundary. | Wait for an accepted authenticated-parent/positive-height Core activation interface; do not edit `core.rs` or fabricate roots. |
| `R3-PARENT-001` | P0 | A04/Core upstream | **Blocked upstream.** `Core::new` rejects an authenticated application genesis parent; the existing offline h1 owner accepts only the narrow synced empty-prefix bootstrap. A real non-empty ordinary h1 cannot safely enter P→D from the current process constructor. | Obtain an approved positive-height application-prefix handoff or a Core-owned ordinary activation seam; rerun parent/JMT mutation vectors. |
| `R3-AUTH-001` | P1 | A03 | **Partial.** Existing candidate driver proves Core-owned D→same-owner AuthorityVote ordering for a synthetic ordinary fixture. It does not prove a native process proposal or signer custody. | Re-run with a real native P result after upstream parent/body interfaces are accepted. |
| `R3-HOOK-002` | P1 | A03/Core API | **Open.** The compatibility `Unsupported` callback still receives `&mut Core`, and the request API exposes no claim-status query. A hook can therefore mutate volatile Core state or consume the linear request and silently return an empty fallback without the driver proving that fact. | Freeze an immutable ordinary fallback or Core-owned claim/whole-state digest; retain the current path as candidate-only and fail closed on any observable mutation/effect. |
| `R3-CUSTODY-001` | P0 | A05 (forbidden surface) | **Open/blocked.** The process fixture contains a feature-gated raw test key and no remote signer-intent/custody contract. A03 does not modify signer, SafetyStore, checkpoint, watermark, or finality code. | A05 must accept the signer-intent interface; invalidate any dependent R3 evidence until then. |
| `R3-RESTART-001` | P0 | A02/A05 | **Blocked upstream.** The process wrapper starts from a fresh root and rejects unresolved/non-empty restart state; there is no accepted body-resolution-by-target or whole-node recovery owner. | Consume an accepted A02 replay/body handoff plus A05 recovery contract; execute SIGKILL/response-loss matrix. |
| `R3-MUTATION-001` | P0 | A03/A02/A04 | **Open.** No complete process corpus covers body, parent/JMT, validator set, parameters, runtime profile, authority affinity, WAL/path, and response-loss mutations. | Preserve each mutant and run the corpus only against an accepted, source-bound adapter. |
| `R3-EVIDENCE-001` | P0 | A03/A06 | **Open.** No independent review/replay or authorized clean-clone evidence exists for this package. Local Cargo, Rustc, and Rustfmt executables are absent. | Run exact commands in a clean authorized clone and obtain independent review; no closure claim before that evidence. |

## Local interface freeze

The only consensus-facing interface added in this package is the A03-owned additive hook
`CandidateEffectDriverHooksV1::validate_ordinary_payload_v1`. Its default
implementation delegates the pre-existing seal-only hook, preserving source
compatibility. `Unsupported` is an integration marker and invokes the legacy
`validate_payload_v1` fallback only when Core's SafetyState is unchanged and
it returns an empty effect list; any detected SafetyState mutation or
non-empty list is rejected. A hook that claims the linear request and then
silently returns an empty fallback is not detectable with the current public
request API, so that liveness/claim residual remains open.
It is explicitly not an execution result or a closure claim. The new negative variants do not construct a Core Valid proof,
Safety authority, signer intent, finality receipt, or application commit
authority. Production and activation constants remain unchanged and false.
Because the negative variants are adapter-returned candidate values rather than
Core-issued proof tokens, an accepted production handoff must additionally bind
them to an authenticated body/evidence ticket; this package does not claim that
forgeability gap is closed.

## Upstream interface requests

1. `ICR-G1-R3-A02-001` requests an A02-owned, restart-safe authenticated body
   and evidence resolution ticket bound to the exact replay target, namespace,
   frame fingerprint, parent/context, and generation. It must distinguish
   `Unavailable` from deterministic corruption/conflict and must not mint a
   Core acknowledgement or expose a raw key.
2. `ICR-G1-R3-A04-001` requests an approved positive-height application-prefix
   handoff (or equivalent Core-owned activation seam) that binds chain,
   genesis, parent header, JMT/state root, validator set, parameters, and
   runtime profile before an ordinary non-empty proposal is admitted. A03
   requests routing/acceptance; it does not edit A04/Core surfaces.
3. `ICR-G1-R3-A05-001` requests an A05-owned remote signer/checkpoint custody
   receipt bound to the exact Core intent, external predecessor, signer
   profile, and response-loss recovery state. It must not expose a raw key or
   silently retry an ambiguous signature.

All three requests are `proposed` and have no accepted interface digest. Per the
merge queue, M3/A03 cannot close while the A02 interface digest is unaccepted.

## Commands and results

The following commands were run against the bound worktree; no result is
inferred from an unavailable toolchain.

| Command | Result |
| --- | --- |
| `git fetch --all --prune` and targeted `git ls-remote` for candidate/main/Plan/PR refs | **PASS**; candidate remained `6e0189e…` / tree `efea864…`; current PR #8 is `8bfd73f…` / tree `cfedd363…` and PR #9 is `97a96c0…` / tree `3bd490ef…`; no duplicate R3 PR was found |
| `bash scripts/project-preflight.sh --audit` before the native path was added to the local topic scope | **FAIL (expected scope check)**; reported `complete.rs` and `durable.rs` outside `.git/PROJECT_TOPIC`; CI/x230 and cargo-offline policy checks passed |
| `bash scripts/project-preflight.sh --audit` after the owned native path was declared | **PASS**; `warnings=0 errors=0` |
| `bash scripts/ci/check_canonical_development_plan.sh` | **PASS** |
| `bash scripts/ci/check_replay_to_core_r2b_contract_v1.sh` | **PASS** (contract-only; not an A02 acceptance) |
| `git diff --check` | **PASS** at each recorded edit checkpoint |
| focused `cargo test …` driver/process/native commands | **NOT RUN**; `cargo` is absent (`command not found`, exit 127) |
| `cargo fmt --all -- --check` | **NOT RUN**; `cargo` is absent (`command not found`, exit 127) |
| `sha256sum config/consensus-mainline.json RELEASE_READINESS.md` | **PASS**; `19baef8a393d235b4f87a1351e2b8cdf2e7bb1f2eea8770ecc67d3e18966c6be` / `1659693f0662f8a19b526c602379fe9fa54626afefe33d35917983f699f2dfa4` (unchanged authoritative truth) |
| `bash scripts/ci/check_trnm_native_execution_v0_boundary.sh` | **NOT RUN TO COMPLETION**; static contract checks reached the Cargo graph at line 342, then `cargo: command not found` (exit 127) |
| `bash scripts/ci/check_trnm_native_application_boundary.sh` | **NOT RUN TO COMPLETION**; `cargo metadata` is unavailable (`cargo: command not found`, exit 127) |
| `python3` TOML parse of the R3 manifest | **PASS**; manifest parses with `status=blocked-upstream` and all production/exit flags false |
| independent clean-clone replay | **PENDING/OPEN**; required reviewer and Rust environment are unavailable |

The initial preflight scope error was resolved locally by the untracked topic
allow-list; it is not a repository truth change and `.git/PROJECT_TOPIC` is not
part of the package commit.

## Intended changed paths (package branch only)

```text
docs/development/packages/TRNM_G1_R3_A02_INTERFACE_CHANGE_REQUEST_001.md
docs/development/packages/TRNM_G1_R3_A04_INTERFACE_CHANGE_REQUEST_001.md
docs/development/packages/TRNM_G1_R3_A05_INTERFACE_CHANGE_REQUEST_001.md
docs/development/packages/TRNM_G1_R3_ORDINARY_PROPOSAL_AUTHORITY_GAP_LEDGER_V1.md
docs/development/packages/TRNM_G1_R3_ORDINARY_PROPOSAL_EXECUTION_TARGET_V1.md
docs/development/packages/trnm-g1-r3-ordinary-proposal-authority-v1.toml
trillionnium/crates/trnm-native-execution-v0/README.md
trillionnium/crates/trnm-native-execution-v0/src/complete.rs
trillionnium/crates/trnm-native-execution-v0/src/durable.rs
trillionnium/crates/trnm-poco-node/src/effect_driver.rs
trillionnium/crates/trnm-poco-node/src/lib.rs
```

## Negative, fault, and replay record

The retained local mutants are represented by the focused driver tests for
explicit `Unavailable` and `DeterministicallyInvalid` outcomes, plus legacy
`Unsupported` hooks that attempt to emit a timer effect or mutate Core's
SafetyState through an early `PayloadValidated::Unavailable` callback. They
assert fail-stop and that no signer call, checkpoint CAS, or broadcast occurs;
the mutation test also retains the changed SafetyState as evidence that the
guard—not a benign empty fallback—caught the attempt. Because the compatibility
callback still receives `&mut Core`, volatile block-tree/cache mutations that
do not alter SafetyState remain an unclosed trusted-hook residual.
The native runtime-attempt mapping retains separate state-unavailable and
invariant branches in the candidate diff, but its injected fault tests have
not run and the broader complete-error mapping remains open.
The following required vectors remain **not run/open**: empty or malformed
body; payload/receipt/evidence/state-root substitution; parent/header/JMT
mutation; validator-set/parameter/profile mismatch; foreign Core or seal
authority; duplicate claim; P-commit/D-delivery response loss; SIGKILL and
restart; WAL/path/inode replacement; and remote-signer custody.

## Non-claims and downstream invalidation

- `production_candidate=false` and `production_consensus_activation=false`
  remain authoritative; no truth file was changed.
- This package does not claim finality, application apply, checkpoint,
  anti-rollback, network, signer, or release readiness.
- Existing synthetic process-D→Vote evidence is not upgraded by the local
  tri-state API. Any R4/A06 evidence that consumes a future A02 body or Core
  activation handoff must be regenerated after its interface digest is
  accepted.

## Terminal decision

`BLOCKED_UPSTREAM` is the valid terminal status for this run: the required
A02 handoff has no accepted interface digest, and the current process
constructor supplies no authenticated native application parent for a real
non-empty ordinary h1. The local tri-state slice is candidate-only and awaits
independent review; `R3-MAP-004` has only a partial mitigation and remains
open until all native entry points retain typed dispositions. The next
deterministic action is to submit the three ICRs, wait for accepted
versions/digests, then rerun the body/parent/mapping/mutation and restart gates
from a fresh clone.
