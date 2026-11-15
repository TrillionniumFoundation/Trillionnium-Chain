# Explicit retained W1 v2 guest build

The `trnm-w1-zk-host-v2` feature `retained-v2-guest` embeds the original complete
SDK program from
[the full v2 observation](../../../evidence/pon-w1-full-v2-20261105/README.md).
It does not compile a new guest. The normal default path still calls
`risc0_build::embed_methods()` with the original locked guest build.

```sh
cargo build --release --locked --offline \
  --manifest-path formal/pon-nakamoto-v1/w1_zkvm/Cargo.toml \
  -p trnm-w1-zk-host-v2 --bin w1-staged-prover-v2 \
  --features retained-v2-guest
```

The retained path reads only
`evidence/pon-w1-full-v2-20261105/guest.bin` from this repository. It requires a
regular file of exactly 375,928 bytes, SHA-256
`25718312ec3c6f5219d832e3516adfb5f82983156f669c5e7daa15bd22d1798f`,
and the original fixed v2 SDK ImageID. This is the SDK's complete `R0BF`
`ProgramBinary`, containing the user and kernel ELF files, rather than a bare ELF
file. The build checks its ImageID with the already locked SDK binfmt library,
copies the verified bytes into `OUT_DIR`, checks the copy, and generates the
normal method constants from those bytes. It rejects `RISC0_SKIP_BUILD`.
The host repeats the byte and SDK ImageID checks before any proving stage.

`OUT_DIR/guest-build-provenance.json` and the host's
`EMBEDDED_GUEST_IDENTITY_VERIFIED` row record the explicit mode. They do not
certify proof generation, independent proof verification, business completion
or payment. The retained path permits a new proof of this exact original guest;
every fresh segment and recursive operation must still run and be observed.
The independent [fixed v2 verifier](../w1_v2_verifier/src/image.rs), strict
expected-artifact binding and full successful claim checks are unchanged.

The [historical rebuild recipe](../../../evidence/pon-w1-pinned-rebuild-20261105/README.md)
requires its actual source path and cache remapping. A guest rebuilt in another
physical checkout is not presumed to have the same image. Reproducing that
historical build remains a separate task; this feature makes no new guest
reproduction, performance, deployment or security qualification claim.

Parallel stages take explicit `RAYON_NUM_THREADS` from the caller:

```text
w1-staged-prover-v2 --r0vm PIN prove-parallel DIR MAX_NEW WORKERS
w1-staged-prover-v2 --r0vm PIN compress-balanced DIR WORKERS
```

There is no positional thread-count argument. Each command checks workers in
1 through 4 and a maximum of eight requested Rayon threads in total. These are
research request bounds; an external supervisor must enforce the actual CPU,
memory, original absolute deadline, descendant cleanup and publication limits.
Sequential and balanced measurements need distinct fresh checkpoint trees.
An incomplete parallel batch blocks dispatch. Cold recovery of an already
completed batch re-verifies its actual seals and the complete original prefix;
it does not turn a previously failed or canceled operation into on-time success.
