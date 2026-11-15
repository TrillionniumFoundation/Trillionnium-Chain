# Live V5 witness and historical provider readback: source and interrupted observations

Status: **HOLD**. Production activation remains false. The implementation and
static checks below do not establish a functioning witness daemon, ordinary M15
entry, actual external-effect reconciliation, or independent recovery custody.
**No Rust libtest case executed in either native attempt in this archive.**

## Exact source

| Item | Identity |
| --- | --- |
| C5 parent | `6ac9a79c2fb37d6102c526c354fe2d448a9f4e6d` |
| Runtime change | `225ab38e1e5f7e0852a28372bd8dd769eec1084b` |
| Runtime tree | `42261bc65d7725458d58b491b71b30a3fe27b755` |
| Reviewed metadata and observed source | `b7ed54cdb7793ca0a22f85350fecc0162d089fba` |
| Observed source tree | `71953d88ccf81bab48996e4f5128f620a448fc56` |
| Frozen Root source inputs | 43 files; review base is the runtime change above |
| Frozen Root snapshot digest | `e1ee97550a6ec20b79f8d917793f2b4268772864e611448a6846869999bcb19b` |

This evidence-only successor preserves the original observations. It does not
relabel them as results for this successor or for a later combined candidate.
The seven records under [observations/exact-b7ed](observations/exact-b7ed)
contain before/after verification of the complete committed worktree: 28,327
tracked entries and 2,578,753,326 tracked bytes. The original command arguments,
return codes, elapsed times, log lengths, hashes, and raw logs are retained.

After a temporary executor disconnect, the original Git objects and files were
found intact. The clean `b7ed54` source, all 43 frozen file hashes, both original
commit object identities, and all five provider inputs were checked again.
[recovery-manifest.json](recovery-manifest.json) records this later integrity
check separately; it is not a substitute for an interrupted runner's missing
source-after record. No source or original observation was changed by recovery.

## Implemented component boundary

The [provider readback bridge](../../trillionnium/crates/trnm-pon-node/src/root_recovery_v3/witnessed_v5/provider_readback.rs)
connects the existing V4 historical provider identity to `WitnessedRootOwnerV5`.
It requires live authenticated V5 context before and after historical enrollment
lookup, checks the same Root head within that lookup, derives the internal V4
floor from the just-authenticated V5 context, and separates provider keys from
the retained Root/service and witness roles. It preserves budget identity and
fences the V5 owner on failure.

The [shared V4 reconciliation path](../../trillionnium/crates/trnm-pon-node/src/root_recovery_v3/effect_readback_v4.rs)
revalidates the historical enrollment on both sides of the provider callback.
V4 journal bytes, signed domains, pending-read persistence, original operation
and material identity, and `Unknown` semantics are retained. The new entry does
not expose an inner V3 owner or grant effect dispatch, retry, or M15 authority.

V5 constrains the Root state and historical identity. **It does not bind each
provider journal head to the witness.** A cold rollback of that separate journal
or loss of provider history still requires external reconciliation of the same
operation. A signed provider receipt remains a provider declaration. It does not
prove that a real payment or other effect occurred, and `Unknown` does not grant
permission to retry an effect under a new nonce.

The eight added [native test methods](../../trillionnium/crates/trnm-pon-node/tests/root_witness_provider_v5_native.rs)
cover created/cold owners, lost read replies, `Unknown` after `Applied`, unavailable
and regressed witnesses, regression during a provider read, cross-role keys,
budget/cancellation replacement, and exact historical material/operation. They
use real PQ signature operations and SQLite/files with an in-process witness
fixture. Their source was reviewed; their execution remains outstanding here.

## Completed observations

| Observation | Actual result and scope |
| --- | --- |
| Exact default and all-feature locked Cargo metadata | Both commands exited 0; the default graph has 177 packages and 26 workspace members |
| Exact workspace formatting | `cargo fmt --check` exited 0 |
| Exact source-integrity rejection controls | 43 tests passed |
| Exact Root register and V5 runner inventory controls | 47 tests passed: 43 register controls and 4 runner controls |
| Exact repository link checks | 6,782 local Markdown links checked; 1,484 Rust files and 26 workspace members reported; activation false |
| Exact V5 corpus omission control | One unittest method passed; it covers eight source paths under three omission mutations and an old-pin mutation |
| Complete corpus checker | 1,162 immutable pins retained; result `HOLD_NO_GO` |
| Earlier complete corpus control suite | 60 tests passed in 1,231.776 seconds; this preliminary run lacks a complete before/after recorder and is not an exact-`b7ed54` whole-tree run |
| PQ provider preparation | Original preparation script built OpenSSL 3.5.9 and passed ML-DSA-65 sign/verify plus wrong-message rejection; no Root native test is implied |

The original earlier corpus failures caused by incomplete sparse materialization
are retained alongside the later complete-tree checks. All original observations
are under [observations](observations); no failed log was replaced by a passing
summary. The [provider receipt](observations/setup/pq-provider/provider.json)
records the archive, preparation script, CLI and library identities and the
1,197-second preparation. The original CLI and static libraries remained outside
this evidence directory; their five receipt inputs were verified again during
recovery. The retained compiler qualification archive belongs to the SQLite
layout witness and does not constitute a successful Root test binary.

## Native attempts and incomplete gates

| Attempt | Actual terminal observation |
| --- | --- |
| [Original loader environment](observations/native-v5-b7ed/interrupted-attempt.json) | The unmodified SQLite boundary rejected qualification because the Cargo loader set omitted the canonical toolchain top-level `lib`; the owned runner was interrupted with exit 130 before Node codegen/libtest execution |
| [Corrected loader environment](observations/native-v5-b7ed-loader-fixed/interrupted-after-build-failure.json) | Absolute `RUSTC` and canonical toolchain `LD_LIBRARY_PATH` qualified the original layout witness; the fresh-witness Cargo command exited 101 after 280.698 seconds with Node and MVCC rustc each reporting signal 9/SIGKILL; the subsequently started durable-witness build was interrupted with runner exit 130 |

The underlying SIGKILL cause was not established. The completed Cargo command
did not time out. The source-before checks succeeded, but both interrupted
runners lack a completed source-after check and final summary. The corrected
attempt retains the [actual command receipt](observations/native-v5-b7ed-loader-fixed/commands.json),
raw stdout/stderr, qualification output, exact-symbol results, and static archive.
Neither attempt ran a libtest case. A planned single-job third attempt did not
start in this environment.

The remaining native inventory is 17 fresh-witness, 12 durable-witness, and 8
provider-readback methods in the complete V5 runner, plus the 14 affected V4
`root_effect_readback_v4_native` methods. Strict Clippy remains outstanding for
this source. Later execution must retain the original profiles, features,
qualification policy, complete test inventories and budgets, and record its own
exact source before and after. Earlier static or provider-smoke results cannot
be promoted into a pass for these 51 native methods.

## Unchanged exclusions

The source does not establish independent administrators/devices/backups,
survival of a freshness authority outside a shared restore domain, new recovery
entropy, real external-effect truth, a durable witness daemon or wire codec,
ordinary M15 product assembly, or whole-chain lifetime/cryptographic guarantees.
Restoring every authority remains an explicit counterexample. The conditional
component and its pending semantics must not be described as completed system
security or production activation.
