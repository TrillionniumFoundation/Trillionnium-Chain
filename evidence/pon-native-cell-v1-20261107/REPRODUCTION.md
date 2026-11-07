# Native bounded Cell retained validation

Final native suite: **12 passed, 0 failed, 0 ignored**, execution 9.48 s.
The A2 and A3 executions repeat these tests and are not additional tests.
Final A4 Clippy (node library + actual binary + this integration test, all features,
warnings denied), workspace formatting, and locked/offline Cargo metadata all pass.
Raw command arguments, exit codes, durations, stdout and stderr are retained.

There are 12 retained case directories, **11 distinct complete
Cell claim byte strings**, and **55 distinct full W1 tile proofs**,
deduplicated by SHA256. Each Cell claim contains all five native W1 proofs.
The retired-model case is an explicit counterfactual control. All cases are
synthetic research fixtures. These are not independently administered work,
quality, cost, model adoption, delivery, or production activation qualifications.

## Inputs and reproducibility

- a4-cli/native-cases/<case>/owner-admission.json is the separately retained owner
  admission, frozen before producer claim generation. Its SHA is pinned in
  settings-and-context.json. This is separate test-owned input, not independent
  administration or authentication of its origin label.
- claim.json retains all raw W1 proof bytes (hex), complete actual intermediate
  tensors, output, after-state, and after-model.
- settings-and-context.json retains fixed genesis, protocol parameters, task
  profile, state backend, and actual Node-derived parent context.
- History cases include the exact parent.packet and successor.packet. Existing
  Node validation, not producer-advertised parent JSON, rebuilds their states.
- The source snippets use owner-utf8-ascii-token-snippet-v1. This is not
  verification of a Git corpus or a generic multimodal encoder.
- final-source-fence.json pins all ten native source/fixture files, Cargo.lock,
  and the actual tested binary. a4-metadata.stdout is the full exact Cargo graph.
- The fixture generator source and full retained oracle are in the source tree
  under trillionnium/crates/trnm-pon-node/tests. Seven ASCII cases compare all
  numeric stages against Python V2, without accepting Python V2/V3 wire claims.

## Cold replay through the existing ordinary CLI

From an extracted evidence directory and a built trnm-pon-node binary:

    python3 /absolute/native-validation/cold_replay.py \
      --binary /absolute/to/trnm-pon-node \
      --cases /absolute/native-validation/a4-cli/native-cases \
      --output /absolute/path/to/a-new-output-directory

The output directory must not already exist. The script creates three independent
stores, submits retained genuine parent/successor packets with the fixed fixture
settings, and invokes cell-verify-historical in six fresh child processes.
It never runs a prover and does not derive expected context from a claim.
Logical time is used only while reconstructing ordinary fixture chain packets;
Cell historical commands have no clock override and derive time from the verified
parent. All six replay receipts match before/after active-tip changes. Raw child
streams and commands from the actual successful run are in a4-cold-replay/.

## Boundaries

The native verifier executes the fixed integer encoder, 257-dimensional linear
base/router/deltas, recurrence, routing, sampler, STOP/abstain/tool proposals, and
optional masked clipped momentum training. It checks full W1 relations and
recomputes complete stage tensors. It is an explicit bounded Node/CLI entrance;
normal Packet admission and consensus activation are unchanged.

Historical replay has no wall clock or current revocation input. Live checking
covers current native active parent/generation and clock cuts. Current task-owner
authorization, revocation, FinalUse, one-time operation consumption, checkpoint
commit, later production use, actual tools/delivery, consensus eligibility,
quality and work-cost qualification remain outside this entrance. In particular,
the separately tested private Hepta owner does not consume this public native
proof in this evidence. A passing pure verifier can accept the same proof again.

## Failed observations retained

A3 strict Clippy failed on two range-loop diagnostics; the fix preserves all
64x64 padding cells. The first A4 workspace fmt run failed because sparse checkout
omitted an existing fuzz support source; restoring exact HEAD bytes made it pass.
An artifact transfer guard rejected a cold-replay script trailing-newline SHA
mismatch before execution; exact file bytes were then transferred successfully.
Those failures and the successful reruns remain present. No success flags replace
failed raw records.
