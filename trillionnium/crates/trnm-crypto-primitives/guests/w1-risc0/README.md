# Complete W1 transparent-proof research backend

This isolated workspace implements a real RISC Zero guest and a strict local
Composite STARK verifier for the complete existing W1 relation. It is a research
component under the [sole development plan](../../../../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md),
with no Node entry point, production activation or conversion to `VerifiedWork`.
Execution, proof generation, proof verification and adversarial rejection are
reported as separate observations. Missing or failed proof steps are failures.

## Exactly what is proved

The guest directly compiles the same
[`full_relation.rs`](../../src/pon_work/full_relation.rs) that is independently
compared with the three existing native W1 kernels. The thin `relation` crate
provides only fixed parameters and error names; it has no copied arithmetic and
does not import unrelated signature, database or Node dependencies. Native tests
compare those parameters with the actual M01 profile.

The input has exactly 49,640 bytes: the 452-byte public statement followed by all
49,188 PNW1 bytes. The guest checks the full 318-byte header, expected task and
target, A/B/C canonical words, four noise streams, all 512 ordered rank-8 tiles,
every intermediate-value SHA-256 byte and the complete product corrections. It
retains N=64 and q=2^32-5. There is no smaller demonstration relation and no
extra proof nonce in the ticket or block ID.

The public journal is exactly 228 bytes. A statement binds all header fields,
including miner/payout, parent, nonce, target and roots, plus the entire W1
witness commitment. A matching claimed journal is only a cheap rejection gate;
the real pinned proof must authenticate it. Proof encoding and proof randomness
cannot add lottery attempts. The Chain caller must still establish task
eligibility, parent state, difficulty and network context independently.

## Backend security boundary

The manifest pins RISC Zero 3.0.6, exact Cargo dependencies, the official compiler
archive, the official local prover archive, the guest source files, raw ELF,
program container and actual image ID. The SHA-256 accelerator is the fixed
upstream [`RustCrypto-hashes` commit](https://github.com/risc0/RustCrypto-hashes/tree/7fd6900c4f637bd15ee2642dfa77110f8f1ad065).
The guest uses the compatibility kernel from `risc0-zkos-v1compat = 2.2.3`.

W1 still hashes its transcript with **SHA-256**. This does **not** mean the proof
system uses SHA-256 commitments: this backend's segment verifier supports
**Poseidon2**, which is explicitly pinned. The local driver accepts only real
Composite receipts and refuses Fake, Groth16, Succinct, unknown images, changed
parameters and unresolved assumptions. It requires `RISC0_DEV_MODE` to be absent
and disables development mode in the SDK. Only an explicitly named local r0vm is
used; no remote proving service is selected.

The driver retains a size-bounded candidate returned by the SDK even if a later
strict profile check fails, so such a failure can be inspected. A file's
existence never signals successful verification. Only the explicit result after
all checks, with a successful process status, can qualify the observation.

The upstream security descriptions have different scopes and numbers. The
README's 98-bit conjectured headline is the historical value recorded in this
run's initial manifest; it is not a measured security result. The pinned
`risc0/zkp/src/lib.rs` and `prove/soundness.rs` describe 97 conjectured bits at
po2=20 and 95 at po2=24. The current
[official 3.0 security model](https://dev.risczero.com/api/security-model) lists
96 for the RISC-V prover and 99 for recursion. This experiment uses Composite
proofs, not recursion. The actual circuit parameters and segment distribution
must be passed to the pinned calculator and reported separately, including the
calculator's conjectures and its hardcoded degree assumption.

`soundness_report.py` copies hash-pinned upstream formula and parameter sources,
then compiles a small descriptor harness around the unmodified
[calculator source](https://github.com/risc0/risc0/blob/1cc70cf05033a79ebc90f07c679cb4bd1cd301b9/risc0/zkp/src/prove/soundness.rs).
It implements no prover, verifier or cryptographic HAL. It reports the actual
po2 histogram, three upstream f32 estimates and a conditional sum of segment
error estimates. The receipt metadata reader is not a proof check; a separate
real verifier must authenticate the same receipt. An execution-only mode is
explicitly labeled and cannot satisfy the proof-observation checker.

None of those numbers is a PQ128 qualification. Dividing a classical number by
two does not establish quantum security. Fiat-Shamir in the QROM, Poseidon2,
Merkle/FRI parameters, multi-target losses and all allowed prover choices require
their own analysis. Refusing elliptic-curve wrappers and fake receipts does not
make the rest of the Chain post-quantum.

The reviewed core/prover/verifier paths contain no independent hashcash grinding
requirement. That observation has the limited source-review scope recorded in
the [exact extra-grinding review](no-extra-grinding-review.json); it is not an
independent cryptographic audit or inferred from the separate PoVW flag. That
review pins every inspected Git blob and SHA-256, searches nonce/difficulty and
grinding terms, and follows the actual transcript/FRI calls. Final coefficients
are committed and followed directly by 50 query openings and matching verifier
queries; there is no protocol nonce or hash-threshold search. The Poseidon2 RNG's
fixed sampling loop is not Hashcash. PoVW attribution nonces are a different
mechanism and are not introduced into this W1 statement or lottery. This does
not claim that a malicious Fiat-Shamir prover cannot retry different commitment
or blinding choices; those security losses remain outside the measured proof.

## Untrusted receipt bounds

Before generic bincode parsing, `receipt_bounds.rs` scans the complete supported
layout without allocating vectors or strings. It checks every variable length,
known enum branch, segment index, hash name, claim journal and assumptions list.
Only the exact supported Composite layout can reach SDK deserialization.

The research limits are 128 MiB total bytes, 2,048 segments, 262,144 seal words
per segment, po2 from 13 through 20, at most 256 Mi padded proof cycles in total,
exactly 228 outer-journal bytes, and no nested assumption receipts. Empty and
short seals are stopped before the SDK's direct seal-header indexing. These
limits bound accepted decoding shapes and proof dimensions; they are not a
measurement of a publicly affordable CPU or RAM budget.

Budget/profile refusal is labeled **Refused (not evaluated)**. It does not mean
the underlying computation or proof was determined invalid. Malformed encoding
and failed cryptographic checks are distinct observations. No rejected receipt
falls back to complete native W1 verification. The standalone verifier does not
implement Node-wide concurrency, network byte budgets, peer scheduling or
honest-service guarantees; existing native-ingress stress results do not qualify
this new path.

### Separate guest failures, receipt failures and measured CPU

`make-invalid` creates two exact-size, publicly committed negative inputs from
the original valid native fixture. One retains the correct product while
changing the trace; the other retains the correct trace while changing one
canonical product word. Both rebind the complete witness commitment and must
reach their exact native late failure. `reject-input` then sends these inputs
to the unchanged real guest without a native replay on that measured path.
Only the original guest's exact `Work(Transcript)` or `Work(Product)` panic is
a successful negative control. Unavailable IPC, timeout, another error or
successful guest completion fails the control. This is guest execution
evidence, distinct from rejecting a corrupted cryptographic receipt.

The receipt verifier and each adversarial receipt case now record Linux
process CPU time over all verifier threads as well as wall time. The external
prover's child-family CPU and waited-descendant RSS stay in `measure_step.py`'s
separate process record; the verifier-process clock does not count child r0vm
work. Version 2 process records keep the wrapper's timeout status, actual child
return code, reap state, cleanup actions, raw output sizes and SHA-256 digests.
The fresh Linux wrapper is the subreaper for its one child family and checks
the original process group even if the host exits before r0vm. A leader that
leaves a live descendant cannot make the observation succeed; bounded TERM/KILL
cleanup and adopted child terminal states are retained before hashing raw logs.
The real subprocess controls exercise nonzero exits, SIGTERM tail output,
SIGKILL, failure before spawn, and both a successful and killed leader leaving
its child alive. They simulate no proof result.

`analyze_costs.py` compares the actual receipt verifier and slowest tested
receipt rejection with all four original native kernels' 31 fresh wall-time
samples for the same input on the current runner. `last_seal_tamper` measures
the decoded-object verification component;
`last_seal_tamper_wire` additionally parses the actual mutated bincode bytes
under the unchanged allocation and cycle bounds. Attack construction is outside
both timers. Neither includes public network admission, which is not integrated.
The readback reports complete raw proof bytes and payload serialization lower
bounds at explicit modeled bitrates.
Those lower bounds are not measured P2P/WAN propagation, account for no packet
overhead or gossip fanout, and authorize no receipt format in the current Node.
The original Node still expects its existing PNW1 work encoding.

The same readback binds the actual cryptographically verified segment profile
and receipt SHA-256 to the existing `soundness_report.py` output. That is the
single pinned upstream Rust f32 calculator, executed verbatim for all three
conditional models; there is no second float64 formula implementation. Its
103-column tap set and hardcoded degree 5 remain assumptions of that upstream
calculator. Conditional segment union estimates are neither a complete composed
soundness proof nor quantum-bit estimates. Source-specific 96/97/98-bit
descriptions remain separate in `backend-source-review.json`; no headline is
promoted to an acceptance level. Hash security, quantum Fiat-Shamir and work
hardness remain outside that numerical readback.

### Explicit reuse for an unchanged rebuilt guest

If no `receipt-reuse.json` is present, the research workflow makes one new
complete segmented attempt under a 3,600-second cap. The first monolithic
5,400-second attempt timed out without a receipt; it is retained as a failure
and is not eligible for reuse. A reviewed reuse
declaration instead pins one successful original GitHub run, source commit,
attempt, artifact ID/digest, and every required receipt/input/source/prover
observation file by exact SHA-256 and size. GitHub metadata is checked with the
workflow's temporary read-only Actions token; it uses no user secret or signing
key. An expired, absent, failed or mismatching declared artifact fails; there
is no silent proof generation fallback.

Every reuse run still builds the locked guest and host from the current exact
head, then checks the new raw ELF, program image, image ID and freshly generated
PWG1 input against the original proof's reviewed bytes. It independently
verifies the real receipt, runs the current receipt attacks and real guest
negatives, and repeats the native benchmark on the current runner. The old
prover outputs stay under `prior-proof/`; their source and runner are separate
from new verification costs. Observation schema v2 explicitly records whether
a proof was generated in the current run. Preparation/hash agreement alone
never authenticates a receipt. This optional research reuse rule changes no
required acceptance gate, consensus parameter or production-readiness flag.

### Same-image segmented attempt after the original timeout

The [original observation](../../../../../evidence/pon-w1-risc0-segmented-20261027/original-attempt.json)
pins run 40482711995, attempt 1, source d96138532b656d767d1ef46f6db86e7effae485e
and its complete retained artifact. Actual unchanged-guest execution used
13,364,385 user cycles over 62 segments at po2 limit 18. The subsequent actual
prover reached the 5,400-second cap without a receipt or a verified proof.
Its original process wrapper did not reliably reap an orphaned r0vm at timeout;
its tiny recorded CPU/RSS values are **not** a measurement of the real prover.
The root cause of that run's failure is unknown. The official SHA-256 syscall
accelerator and the relation's bounded pseudo-Mersenne reduction were already
present, so neither missing optimization is established as its cause.

The successor retains the exact guest source relation, N64/R8/q, compiler,
Cargo graph, raw ELF, image ID, SHA accelerator, Poseidon2/FRI parameters and
public PWG1/PWJ1 encoding. `export-segments` executes the complete original
guest through the pinned SDK and saves every actual serialized Segment with
its order, dimensions, byte count and SHA-256. Execution remains distinct from
proof. The local trace export is limited to 32 MiB per segment and 512 MiB total;
a larger real export fails with its partial files retained.

`prove_segments.py` owns exactly two independent local host/r0vm workers, each
with RAYON_NUM_THREADS=2 and a 300-second per-worker deadline. It first requires
at least four effective CPUs and eight GiB observed available memory, reading
the actual cgroup-v2 membership, mounted hierarchy and all visible ancestors.
Unknown controller limits fail the resource precondition. This precondition
is not a proof that peak usage will fit. There is no smaller-profile fallback,
detached worker, new proof nonce, PoVW job or extra grinding search.

Each worker produces and cryptographically checks its actual segment receipt.
A retained successful segment is explicitly **not a complete W1 proof**.
Assembly requires every original index, exact session/image/input identities,
bounded receipt shapes and the expected complete session claim. It discloses
the final output only after equality of its cryptographic digest, following
the pinned SDK's claim construction. The original `strict_verify` then checks
the complete Composite receipt, including every STARK, ordered pre/post-state
continuation, Halted(0), pinned initial image, exact full journal, commitment
parameters and empty assumptions. Only that successful check can create the
final receipt file. Independent verification and all receipt attacks still run.
The [primary-source inventory](backend-source-review.json) records the exact
SDK APIs and claim-chain sources underlying this assembly.

One outer 3,600-second cap covers export, every proof worker, assembly and its
complete verification; work scheduling also stops at 3,500 seconds. This is
less than the original cap, not a rerun under a larger allowance. All subprocesses
inherit the wrapper-owned group. Real per-stage exit statuses, waited-family
CPU and RSS, raw backend progress, partial assets/receipts and terminal failures
remain in the artifact. The existing upstream `proc_group_sampler.py` is the
single active resource observer. The outer wrapper samples its fresh group at
15-second intervals and before/after cleanup, reads no environment or command
line, and checks `/proc/self/stat` against local PID/group/session identity
before reading numeric resource entries. A namespace mismatch or unavailable
sample is UNKNOWN with null RSS, never an invented zero. Original local PIDs
continue to own signals and waits. RSS sums may include shared pages and samples
miss possible peaks; these are not physical group memory or a cgroup peak.
The phase subreaper additionally accounts for descendants orphaned by a failed
host, with final file hashes taken only after group cleanup. Earlier sampler
RED/GREEN evidence is retained under its original source hashes and does not
represent a measurement by this merged observer.
No claim of faster proving or a complete receipt follows from this scheduling
change until the real bounded CI attempt finishes.

## Reproduction

Run from the repository root with a new output directory. The installer accepts
only Linux x86_64 and verifies the entire compressed archive before executing a
downloaded program. It preserves the official linker hard links, which are
required by the guest compiler even with the explicit host BFD linker wrapper.

```sh
bash scripts/project-preflight.sh
backend=trillionnium/crates/trnm-crypto-primitives/guests/w1-risc0
rustup toolchain install 1.95.0 --profile minimal --component rustfmt,clippy
cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-crypto-primitives full_relation
python3 "$backend/install_backend.py" --dest /new/explicit/backend
python3 "$backend/build_guest.py" \
  --cargo "$(rustup which --toolchain 1.95.0 cargo)" \
  --guest-rustc /new/explicit/backend/guest-compiler/bin/rustc \
  --cargo-home /new/explicit/cargo-home --target-dir /new/explicit/guest-target \
  --host-linker "$backend/host_linker_bfd.sh" --jobs 1
cargo +1.95.0 build --release --locked --manifest-path "$backend/Cargo.toml" \
  -p trnm-w1-risc0-host
cargo +1.95.0 test --release --locked --manifest-path "$backend/Cargo.toml" \
  -p trnm-w1-risc0-host
```

The host supports `bake`, `execute`, `prove`, `verify`, `audit`, `export-segments`,
`prove-segment` and `assemble-segments`. `bake` wraps the raw ELF in the official v3
program container and compatibility kernel. All later commands require the
manifest's actual image ID. A different compilation must be reviewed and pinned
before acceptance. The example fixture uses an all-`ff` research target and
synthetic context; it is not an eligible production block.

The dedicated
[GitHub Actions workflow](../../../../../.github/workflows/pon-complete-w1-proof-research.yml)
executes the complete sequence on the exact PR head, uses no secrets or signing
keys, and retains real ELF, input, receipt, process costs and raw failures. Its
concurrency key is the exact head, and it does not replace required baseline
gates. `measure_step.py` gives each command a separate process observation and
terminates only its own process group on timeout. `check_observations.py` requires
the actual native journal, real positive proof, independent verification and all
adversarial controls. Uploading a workflow alone is not proof evidence.

After a successful independent verification, run the parameter calculation:

```sh
python3 "$backend/soundness_report.py" --receipt /actual/run/receipt.bin \
  --out /new/run/soundness --rustc "$(rustup which --toolchain 1.95.0 rustc)"
```

For a run that only completed execution, `--execution-observation` can instead
read the host's actual `execute.stdout.log`. That report has
`model_input_kind=execution_only_metadata` and asserts no completed proof.
The checker accepts only one result of the expected schema and operation from
each raw stdout log; information lines remain intact, while missing or duplicate
result lines fail. Its adversarial controls run with:

```sh
python3 -m unittest discover -s "$backend" -p test_observations.py -v
```

The local [full experiment evidence](../../../../../docs/protocol/pon-nakamoto-v1/evidence/w1-complete-risc0-20261027/README.md)
includes both real program images, the fixed input/journal, source correspondence,
execution and native costs, failed builds and the original 1,800-second proof
timeout. A separate hosted proof run must retain its own status and resource
record; it does not turn that timeout into a local success.

## Performance interpretation

Record, side by side for the same input: native complete W1 replay, actual guest
cycles/segments, proof generation time and resource use, proof bytes, independent
verification, and the slowest tested invalid-proof rejection. Composite proof
verification grows with segment count. A faster guest alone does not establish
better throughput or repair the cheap-forgery/expensive-rejection problem.

In particular, an attacker can reuse an available real receipt and corrupt a
late seal very cheaply. The cost of rejecting that variant must be measured;
the honest one-time proving cost cannot be charged to every attacker submission.
If native N=64 W1 is already cheaper than this proof verifier, this backend does
not meet the throughput or permissionless-ingress objective for that workload.
The full relation, pinned guest and real proof are necessary evidence for the
candidate, not a substitute for that cost comparison or work-hardness analysis.

The separate [controlled loopback cost helper](LOOPBACK_COST.md) requires two
actual original-host verifications around bounded TCP transmission. Its current
finite controls use explicitly synthetic bytes; complete-proof propagation is
still unobserved. Its CI wiring remains a proposal until the original proof run
is terminal and an exact reviewed receipt reuse or segment recovery is available.
# Same-session continuation successor

The [bounded continuation protocol](CONTINUATION.md) retains the original
source-5d9578 failed run and its 26 actual partial receipts. It adds exactly
two independent missing-segment budgets and requires unchanged native full
Composite assembly, actual hostile-proof audit and separately measured
loopback transfer. The first hosted run failed because fresh guest-start memory
entropy changes intermediate trace states. The v2 successor proves only the
byte-identical original trace and keeps fresh execution as a separate complete
relation cross-check. Its new heavy run remains **NOT_RUN** at source freeze;
45 local provenance/process controls are not a complete proof. See the
[retained failure and source evidence](../../../../../evidence/pon-w1-original-trace-repair-20261027/README.md).
