# Complete P3 proofs before actual development Node admission

## Decision and scope

This standalone research crate connects the complete component-5 SHA schedule
proof and component-4 packed arithmetic proof to the **actual** `trnm-pon-node`
library. It generates a fresh native packet using `Node::make`, verifies both
real polynomial-commitment proofs against independently supplied expectations,
then invokes the original `Node::admit` and `Node::activate`. Its SQLite-backed
Node, recovery, duplicate and reorganization behavior are real implementation
paths, not verifier stubs or an imitation state machine.

**Qualification remains HOLD_NO_GO. All five production gates remain open.**
The profile is `w1-pnh1-native-node-scheduled-p3-research-v1`, for a fixed PNH1
research statement and isolated development Node directories. The runtime
workspace, production dispatch, configuration and qualification flags are
unchanged. This does not add PGH2/growth support, a production network endpoint,
a global admission service or a production-owned I/O qualification.

Fresh packets still undergo the original native W1 checks. Exact duplicates
follow the original Node shortcut for an already admitted identical packet;
they are not counted as a fresh FullLimb replay. The P3 certificate is an
additional admission condition. This conjunction currently adds work and does
not demonstrate a production benefit over the native path.

## Current durable proof-start contract

The current CLI requires a separately provisioned common owner and independent
policy for both exercise and cold reopen. Failed starts, cancellations and
interrupted slot writes remain spent across process restarts; concurrent
processes share atomic create-once slots. The complete contract, new diagnostic
namespaces and explicit rollback/QROM limits are in
[PROOF_START_OWNER.md](PROOF_START_OWNER.md). This replaces the old per-process
CLI counter, while all historical measurements below keep their original scope.
The owner directory and every ancestor must remain protected; same-UID and
attacker-writable-ancestor namespace races are outside this local contract.

## What is bound before Node admission

The caller supplies an independent `OperatorPlan`: exact profile, network,
parameters, genesis, 318-byte expected header and 64-byte expected artifact
commitments. The archive and prover do not choose these trusted expectations.
The CLI fixture independently obtains `trnm_pon_node::maintenance()` material, compares
it with the generated packet, and computes its artifact commitments.

`PreparedBundle::new` bounds the native packet to 1 MiB and requires the exact
377,290-byte public statement. Both proof buffers undergo the fixed-profile
structural scan before either allocating proof decode or preprocessing. The
packet must re-encode canonically, its header must equal the trusted expected
header, and its header-plus-PNW1-proof bytes must equal the raw relation in the
public statement. The packet body remains subject to the original Node checks.
Structural scan success alone is never treated as cryptographic validity.

The verifier reconstructs the SHA plan and packed arithmetic preprocessing from
that statement and the independent expectations. It verifies both actual P3
proofs. A private, non-serializable borrowed `VerifiedBundle` can only be created
by successful verification of both components; it borrows the immutable bundle
whose bytes were checked. There is no caller-supplied verification key or
boolean that can construct this capability. Proof verification requires no
Node reference, allowing it to finish before opening or locking a Node owner.

Immediately before admission the adapter checks the live Node network,
parameters, genesis, parent height and target again. It then calls the original
Node admission method; it does not construct the native private verified-work
capability or skip native validation. Changes to the active chain between
proof creation and admission therefore do not make an old receipt authoritative.

The observed evidence is an exact retained input, not a universal theorem about
the P3 construction. The shared-permutation PCS/Fiat–Shamir proof remains open;
see the [lifecycle analysis](../w1_security_lifecycle_r4/README.md).

## Persistence, cancellation and recovery

The archive is a new directory owned exclusively by the caller. It records the
exact packet, public statement and proof envelopes, with a framed SHA-256
operation identity and individual file digests. A final completion marker is
written only after the data files. Files and directories are synchronized.
Reload refuses missing markers, mismatched identities, unsupported profiles,
non-regular files, excessive lengths and altered bindings. The trusted plan
must be supplied again independently; the archive is not a certificate of
admission or chain authority.

At most 16 entries are allowed in an archive, including interrupted operations.
Directory-entry I/O errors fail closed. This bound assumes an exclusively owned
archive; it is not a race-free global quota against another process mutating
the same directory. The file operations do not claim the production-owned VFS,
untrusted-same-UID filesystem isolation or a bound on whole-system disk use.

The CLI verifies both proofs before `Node::open` in both `exercise` and `reopen`.
A rejected certificate or `BeforeProof` cancellation leaves no receiver Node
directory. The original campaign kept failed starts spent only in an in-memory
`WorkStartBudget`; cold processes did not share it. The current explicit owner
charges both CLI paths durably as described above. Neither mechanism establishes
a global quantum-query account, a CPU bound or a service-level rejection guarantee.

The commit boundary has different semantics on its two sides:

| Event | Required observed behavior |
| --- | --- |
| Cancellation before `Node::admit` | No packet admitted; cold reopen still has no such packet. |
| Cancellation after `Node::admit` succeeds | Receipt retains `native_admitted: true`; requested adapter activation is skipped. |
| Cold open after a committed but unactivated packet | Original Node recovery may activate that best committed packet. The adapter does not promise that cancellation survives as non-activation. |
| Exact duplicate | Original native admission path is called; active generation and credited chain state do not increase. No fresh FullLimb replay is inferred. |
| Reorganization to a longer competing branch | A previously admitted packet remains stored but is no longer reported as active. A historical receipt does not reactivate it. |

The original admission receipt schema `trnm-w1-node-adapter-admission-v2` reports invocation
of the native admission path and explicitly distinguishes the fresh-packet
policy from exact-duplicate semantics. It preserves successful native commit
if a later cancellation, activation error or observation error occurs. The
original draft v1 label incorrectly suggested that every duplicate replayed
FullLimb; that draft and its review correction are retained in the evidence.

Opening a Node itself performs native recovery. In particular, `reopen` obtains
a fresh proof capability **before** opening the database, then reports the
current native observation without calling admission. It does not suppress or
rename the original recovery behavior. Checkpoints bound which operations
start after cancellation; they do not interrupt an ongoing PCS call or provide
a hard real-time deadline.

## Actual new complete proof and native fixture

The fixture uses an explicit development genesis time `1,800,000,000` and
observation time `1,800,000,100`, rather than pretending to exercise current
production wall-clock eligibility. `Node::make` produced block
`8c624eed5af1d6eead94ab70a723e8f679da49a4f7f934da4093fbb9cf8044cb`.
The 49,506-byte native relation has SHA-256
`59221e7e334fc536747b9e068bb0d832b4550141c28e45b7cee04c7cf892c845`.

The fixture builder reconstructs all 32,768 cumulative prefix cells in the
original order. It checks all 519 planned SHA messages against ordinary SHA-256
before proving, constructs all 81,920 original arithmetic relations, and runs
the actual native W1 verifier. A new full scheduled-SHA proof and packed
arithmetic proof were then generated for these new bytes, followed by an
independent full verification. This is one fresh complete W1 proof, separate
from the backend's eight-execution ABBA campaign and from retained-proof replays.

| Retained file | Bytes | SHA-256 |
| --- | ---: | --- |
| `sha.proof.bin` | 3,142,981 | `af66da05a9ebab9f0f9224b7b7df19aa6fa8949152fcf714a95797a000728218` |
| `arith.proof.bin` | 454,085 | `b5ae0d59d060d6fd5c965e31f1ee3c082d3e2cad72a1002f191082c27395cb04` |
| Public statement | 377,290 | See the retained fixture manifest. |

Statement plus proof envelopes totals 3,974,356 bytes; the adapter also retains
the original native packet. Proving took 8.777972 seconds and independent
verification 0.862439 seconds in this functional run. These are not ABBA
performance observations or the production resource envelope. The generator is
the same immutable component-5 release binary used in the separately reported
backend comparison, SHA-256
`3c497ff52e42f5904d3aeadd013ae7b6f1f7d43493d5d19f2722ea4d9dde24d1`,
with source identity `eb944645cc3e30af5955edf9dbbcb43488fa38c1`.

The complete retained inputs and proofs are under
[fixtures/node-input-v1](fixtures/node-input-v1/fixture.json). Replays of these
bytes do not become new proving executions or independent input tasks.

## Checks and independent review

The original 12 integration tests exercise full real proofs and the real Node library:
complete admission/activation, duplicate idempotency and cold reopen; false
public arithmetic; independent artifact mismatch; changed header and profile;
precommit cancellation; truthful postcommit cancellation and native recovery;
changed live genesis; a native sibling/child reorganization; corrupt/incomplete
archives; interrupted-operation quota; spent failed work; and two independent
CLI controls proving that refusal or early cancellation never opens Node.
The sibling and child in the reorganization control are original native
packets, not additional newly proved P3 packets.

The original nine separately launched CLI processes also passed five exercise cases and four
cold reopens, including native recovery after postcommit cancellation. These
are retained-proof replays and generate zero new complete proofs.

The focused suite, formatting, locked/offline graph and strict all-target Clippy
are required on the delivered source. The independent review traced actual
Node `admit`/`recover`/`activate` semantics and required both the proof-before-open
boundary and corrected duplicate replay labels. Review scope, exact source
hashes and the complete raw build/check logs are retained under `evidence/`.
These checks are not all repository-wide Node CI or service qualification.

The release build uses `RUSTFLAGS=-C target-cpu=native`, as in the research
backend. The actual `trnm-sqlite-io-boundary` build script reports **UNQUALIFIED:
external native build override CARGO_ENCODED_RUSTFLAGS**. This warning is retained
without changing or bypassing its qualification checks. The experiment uses
ordinary development `Node::open`; it does not qualify the production-owned
I/O boundary, crash guarantees beyond the exercised paths, or an activated VFS.

## Reproduction

Read the repository `AGENTS.md` and run `bash scripts/project-preflight.sh` from
the repository root before editing or building. This is a separate Cargo
workspace and does not add a production-crate dependency on the research code.
The dependency graph is fixed by the committed `Cargo.lock`.

```sh
cd formal/pon-nakamoto-v1/w1_node_adapter_research
RUSTFLAGS='-C target-cpu=native' RAYON_NUM_THREADS=8 CARGO_BUILD_JOBS=2 \
  cargo +1.95.0 test --release --locked --offline -- --test-threads=1
RUSTFLAGS='-C target-cpu=native' CARGO_BUILD_JOBS=2 \
  cargo +1.95.0 clippy --release --locked --offline --all-targets --all-features -- -D warnings
cargo +1.95.0 fmt --all -- --check
```

The current CLI accepts `fixture NEW_DIRECTORY`,
`owner-init EXPECTED_POLICY NEW_OWNER_DIR`,
`owner-status EXPECTED_POLICY OWNER_DIR`,
`exercise FIXTURE PROOF_DIRECTORY NEW_OUTPUT CANCEL_STAGE_OR_none OWNER_DIR EXPECTED_POLICY`,
`reopen FIXTURE OUTPUT OPERATION_DIRECTORY OWNER_DIR EXPECTED_POLICY`,
and `native RAW EXPECTED_HEADER REPEATS`. New output and fixture directories
must not already exist. The last command measures only current native W1
verification with the independent header and includes computing its challenge;
it performs no Node admission. `exercise` exit zero means that its diagnostic
record was written: inspect `outcome`, `error`, `node_opened` and native state,
rather than treating process success as proof acceptance.

A fresh fixture must receive freshly generated full proofs from the sibling
`scheduled_sha_backend` example before `exercise`. Source/binary/fixture
identity, cancellation stages, actual exit states and all failures must be
retained. Neither a historical receipt nor a successful research replay grants
production profile registration, Node qualification or consensus authority.

The separate [shared-cgroup pressure observation](resource_pressure/README.md)
retains 23 incomplete requests and no proof-stage checkpoint under the original
resource quantities. It reports the actual deadline/cleanup overshoot and does
not promote a worker kill into cryptographic rejection.
