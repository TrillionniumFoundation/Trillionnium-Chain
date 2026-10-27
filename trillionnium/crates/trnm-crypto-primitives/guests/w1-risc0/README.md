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
the manifest; it is not an independent cryptographic audit. PoVW attribution
nonces are not introduced into this W1 statement or lottery.

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

The host supports `bake`, `execute`, `prove`, `verify` and `audit`. `bake` wraps the raw ELF in the official v3
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
