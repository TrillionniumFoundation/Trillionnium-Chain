# Pre-execution observation for the fixed three-target build

Prepared for source `1d6a9f9b5e8abd9e86457f45199a4922f9376360`, tree
`4a0314e72ebc45659986d03e7ca2f96cab9399ea`.

The original build-only command is:

```bash
cargo +1.95.0 test --locked --offline \
  --manifest-path trillionnium/Cargo.toml -p trnm-pon-node \
  --lib --test pool_mining --test architecture_delivery_compare \
  --all-features --no-run
```

The recorder label is `chain-final-test-build-only`. This command executes
**0 native tests**. Its successful completion is a build result and must not
increase any native test-pass count.

## Owner sequence

1. Wait for the build owner to confirm that the fixed build-only command has
   completed successfully and competing heavy compilation has ended.
2. Run the observation command below before the original native test commands.
3. Execute the original complete Node library + pool target, and the complete
   13-test architecture target, using their own fixed-source recorder receipts.
4. Use `chain-observation-binaries.py` on each completed native receipt to collect
   its actual `Running` paths and the then-current executable hashes. Compare
   each target's resolved path, SHA-256 and length to the pre-execution record.

The observer has been syntax-checked only. No test ELF has been read or hashed
as part of preparing this script.

```bash
python3 -B /workspace/scratch/768fd621f7e2/evidence-prep/chain-observation-pre-execution.py \
  --receipt /workspace/scratch/768fd621f7e2/chain-receipts/chain-final-test-build-only.json \
  --expected-commit 1d6a9f9b5e8abd9e86457f45199a4922f9376360 \
  --expected-tree 4a0314e72ebc45659986d03e7ca2f96cab9399ea \
  --output /workspace/scratch/768fd621f7e2/chain-receipts/chain-final-pre-execution-observation.json
```

The script requires a completed successful receipt, the exact original argv,
matching source checks before/after, and the original log hash and length.
It requires exactly these three distinct targets from actual Cargo
`Executable ... (PATH)` lines:

- `unittests src/lib.rs`
- `tests/pool_mining.rs`
- `tests/architecture_delivery_compare.rs`

It does not glob a build directory or infer executables from basenames. It
checks that logged resolved paths remain within the recorded target directory,
hashes each regular ELF file while checking for concurrent file changes, and
records ELF architecture plus size and file metadata. Output creation is
exclusive; preserve any existing observation and select a new attempt filename
if another observation is required.

The pre/post comparison can establish whether locally observed file bytes at
the actual Cargo build/run paths agree at the observation times. It is not an
exec-time attestation, a release-binary qualification or an independently managed
deployment result. A mismatch must be reported as a mismatch; it cannot be
repaired by substituting a different cache file.

The architecture run includes its original 14 actual W1 packet preparations and
18 business trials. Its result remains separate from the original four-second /
16-worker and 4,105-block qualification obligations.
