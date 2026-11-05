# Fixed Chain source: native observation checklist

This is a read-only source/receipt audit and execution handoff. No Cargo build,
native test, Clippy run, or deployed-binary qualification was performed by this
audit. Repository files are unchanged.

## Source and existing observations

Final source is `1d6a9f9b5e8abd9e86457f45199a4922f9376360`, tree
`4a0314e72ebc45659986d03e7ca2f96cab9399ea`.

| Observation | Actual source | What the retained receipt establishes |
| --- | --- | --- |
| `chain-final-source-contracts` | Final `1d6a9f9b…` | 365 Python tests in 10 completed groups; source, inventory, repository and formatting commands exited 0; identical before/after source identity |
| `chain-integrated-workspace-clippy` | `bbc940cbdbdd6092158f735565004812ee834281` | Earlier strict workspace/all-targets/all-features Clippy exited 0; no test execution |
| `chain-integrated-node-and-mining` | Interrupted attempt associated with `bbc940cb…` by its separate retarget observation | Recorder remains incomplete (`running`, null exit/hash); separate observation records Ctrl-C/130 and 0 completed tests |

The final static log SHA-256 is
`efdcb3d41ebdeb3522534762d52e450165088066d5647a14dbed0ed33441b4c8`.
Its group counts are 43 + 35 + 98 + 22 + 9 + 51 + 36 + 29 + 22 + 20.
The earlier Clippy log SHA-256 is
`72864193091e5fc0da791bc057766713dbabb9346e4bad1f921b911d12065fcf`.
These hashes were checked against the actual retained raw logs.

## Original commands to execute on final source

Use the existing `/workspace/scratch/768fd621f7e2/native-env.sh`. It fixes one
Cargo build job, no incremental compilation, one Rust test thread, the original
target directory, offline resolution and the pinned static OpenSSL 3.5.9
provider. Preserve existing execution budgets; the recorder itself adds no
timeout or budget.

```bash
source /workspace/scratch/768fd621f7e2/native-env.sh
cd /workspace/scratch/768fd621f7e2/chain

record_fixed() {
  python3 -B scripts/ci/record_pq_native_command.py \
    --kind head \
    --candidate 1d6a9f9b5e8abd9e86457f45199a4922f9376360 \
    --tested 1d6a9f9b5e8abd9e86457f45199a4922f9376360 \
    --label "$1" \
    --output /workspace/scratch/768fd621f7e2/chain-receipts \
    -- "${@:2}"
}

record_fixed chain-final-node-and-mining \
  cargo +1.95.0 test --locked --offline \
  --manifest-path trillionnium/Cargo.toml -p trnm-pon-node \
  --lib --test pool_mining --all-features --no-fail-fast \
  -- --test-threads=1

record_fixed chain-final-workspace-clippy \
  cargo +1.95.0 clippy --locked --offline \
  --manifest-path trillionnium/Cargo.toml \
  --workspace --all-targets --all-features -- -D warnings
```

Labels are exclusive-create: if one already exists, preserve it and use a newly
identified attempt label. Do not overwrite a failed or interrupted receipt.
The recorder verifies every tracked raw byte before and after, retains exact
argv/environment, and hashes the original combined log. A successful command
receipt alone does not establish named test execution.

## Native coverage roster

`chain-observation-roster.json` contains exact test IDs, source paths and Git
blob IDs for every newly introduced Node test function in the source interval
`6ee529046d295e3175f09112492abee373f1f54c` through final `1d6a9f9b…`.
The names were checked against the actual source diff and module declarations.

| Target | Newly introduced nonignored tests | Original Node command coverage |
| --- | ---: | --- |
| Node library | 24 | Included by `--lib` |
| `pool_mining` | 2 | Included by `--test pool_mining` |
| `architecture_delivery_compare` | 11 | Requires its own integration target |

The 26 included tests cover the 7 original mining/materialization fixes and
19 concurrent tests for multiproof reuse, actual worker accounting, Growth
timestamps/preparation/read epochs, schema readback and History reverse spooling.
The original complete Node/lib and pool command retains all preexisting tests;
the 37-name file is the new-test roster, not a replacement for the full command.

### Minimal commands for the additional 11 architecture controls

```bash
record_fixed chain-final-architecture-deadlines \
  cargo +1.95.0 test --locked --offline \
  --manifest-path trillionnium/Cargo.toml -p trnm-pon-node \
  --test architecture_delivery_compare --all-features --no-fail-fast \
  architecture_deadline::tests:: -- --test-threads=1

record_fixed chain-final-architecture-cancellation \
  cargo +1.95.0 test --locked --offline \
  --manifest-path trillionnium/Cargo.toml -p trnm-pon-node \
  --test architecture_delivery_compare --all-features --no-fail-fast \
  dissemination_cancellation_preserves_original_sender_and_receiver_failures \
  -- --exact --test-threads=1

record_fixed chain-final-architecture-complete-material \
  cargo +1.95.0 test --locked --offline \
  --manifest-path trillionnium/Cargo.toml -p trnm-pon-node \
  --test architecture_delivery_compare --all-features --no-fail-fast \
  absolute_deadline_dissemination_keeps_complete_material_in_all_three_modes \
  -- --exact --test-threads=1
```

The first command expects these 9 names, each prefixed by
`architecture_deadline::tests::`:

- `expired_frame_does_not_consume_available_bytes`
- `fragmented_frame_completes_within_one_original_budget`
- `continued_fragment_progress_cannot_renew_frame_deadline`
- `header_and_body_reads_share_the_original_frame_end`
- `cancellation_wakes_a_waiting_receiver`
- `stalled_writer_ends_under_original_deadline`
- `cancelled_writer_does_not_send_a_new_frame`
- `partial_eof_remains_an_error`
- `empty_completion_still_observes_expiry_and_cancellation`

The other two commands each expect their exact selector to execute once.
For those two single-test logs, the existing
`scripts/ci/check_required_native_test.py LOG --test EXACT_NAME` checks the named
execution. That checker intentionally rejects multi-test transcripts, so it
does not apply to the 9-test group or the complete Node run. Retain all actual
test lines and harness summaries for those runs and compare their new-name
subset with the roster.

These 11 controls use loopback TCP, temporary files and fixed signed cells.
They do not mine W1 packets. The largest explicit socket-test buffer is 16 MiB;
frame and round constants remain 2 seconds and 15 seconds. Timing/cancellation
controls retain 90/220 ms deadlines and the original scheduling assumptions.
They are meaningful native socket/framing controls and are not ignored tests.

### Full architecture target remains a separate scope

There are **13 nonignored tests** in the complete architecture target. Besides
the 11 above, it retains:

- `reference_dag_rejects_withheld_body_equivocation_and_changed_signed_history`
- `signed_dag_delivery_comparison_uses_same_native_business_and_confirmation_contract`

The second is the heavier original business test: two workloads, 7 actual W1
packets prepared per workload and 3 samples by 3 modes per workload, giving 18
business trials with public service, retained replay, cold reopen and independent
confirmation. Its original fixed Host checks remain in force. Its CI trampoline
uses the current test ELF and the original native Host runner; local execution
retains the original Host refusal behavior. Running the 11 new controls does not
establish that this complete 13-test target passed. To execute the full target,
use the same Cargo arguments with `--test architecture_delivery_compare` and no
filter; retain the original budgets and all failures.

## Executable manifest after completed native commands

`chain-observation-binaries.py` consumes completed recorder receipts, verifies
their source identity and original log hash/size, and takes executable paths
only from actual Cargo `Running ... (PATH)` lines. It checks that each resolved
path remains under the recorded target directory, hashes the current regular
executable bytes and records ELF class/endianness/machine plus file identity.
It retains observed test-name/outcome lines and harness summaries. It never
executes a binary or discovers one by globbing the target directory.

Run promptly after the original command completes, before another build can
replace the logged files. Add `--receipt` for each completed architecture or
Clippy receipt to include it in the same source observation:

```bash
python3 -B /workspace/scratch/768fd621f7e2/evidence-prep/chain-observation-binaries.py \
  --expected-commit 1d6a9f9b5e8abd9e86457f45199a4922f9376360 \
  --expected-tree 4a0314e72ebc45659986d03e7ca2f96cab9399ea \
  --receipt /workspace/scratch/768fd621f7e2/chain-receipts/chain-final-node-and-mining.json \
  --output /workspace/scratch/768fd621f7e2/chain-receipts/chain-final-executable-observation.json
```

Final evidence should retain:

1. The fixed commit/tree, exact argv, original Cargo graph/lockfile/features,
   toolchain identity, source before/after checks, command status and raw log hash.
2. Every actual logged test ELF path, SHA-256, byte length and architecture,
   together with named executions, failures, ignored cases and harness summaries.
3. The native-env files and actual provider identity. The recorder includes the
   OpenSSL executable path, declared SHA/version, static-link setting and build
   directory, but omits `CARGO_NET_OFFLINE`, `OPENSSL_CONF` and `OPENSSL_MODULES`;
   retain those environment inputs separately. Declared hashes remain distinct
   from measured file hashes.
4. The original failures and incomplete attempts with their own source labels.
   The collector refuses incomplete recorder receipts as qualified inputs.

The manifest reports current post-command bytes at the logged paths. It does
not authenticate exec-time bytes or replace a fixed deployed-node binary
manifest, an independent fault-domain run, or any six-domain acceptance gate.
All acceptance and activation claims remain unchanged.
