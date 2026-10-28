# Complete original W1 Succinct continuation candidate

The original [#534 run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40624205143)
stopped at its fixed 3,500-second work limit. The exact failed artifact was downloaded
and independently checked: 122,897,597 bytes, 656 ZIP members, valid ZIP CRC, SHA-256
`fa9dfea364033d3aefd90f0cd9d2e07e00ef3edf4cc2643720466d3e15427ca5`.

Its 115 actual process terminals comprise preparation, 112 successful recursion
stages, and two SIGTERM-interrupted stages. Eleven recursion stages remain.
The new candidate revalidates all retained STARKs with the original range claims,
then computes the missing stages under the same 300/3,500/3,600-second bounds.
The actual archive reader and six byte-substitution refusals are retained in
[actual-checkpoint-readback.json](actual-checkpoint-readback.json). This is source
and checkpoint validation, not a new complete proof or a fresh native revalidation.

[local-checks.json](local-checks.json) preserves the initial missing-compiler-path
failure as well as 17 Python controls and 34 source-integrity controls.
Actual native compilation, native negative controls, complete proof, measured
invalid-input tails and actual full-certificate transfer must be read from the
new exact-head workflow. Previous successful phases cannot supply those results.

The original complete Composite generation and the failed recursion window are
retained and separately priced. Final reports add exclusive outer phase costs,
including failed work and rechecks; they never add stage cost a second time.
The original PNW1 codec, packet cap, relation, source pins and Cargo locks remain
unchanged. Additional PoW, fake receipts, Groth16, remote proving and production
activation remain disabled. No global minimum hardware cost, WAN qualification,
global worst invalid-input bound or PQ128 security conclusion is asserted.

## Actual local native readback on the frozen candidate

Source `9227dfb93c4745ec77330d94e29a7386c60d0d97` was checked before and
after the native commands. Its 9 Rust unit tests, strict release/all-targets
Clippy, 10 original native controls and 6 new retained-range controls passed.
All 112 exact retained STARKs were independently reverified with the new native
helper in 11.890852185 seconds (11.692368 process CPU seconds); this is a
local revalidation, not proof generation or complete-proof verification latency.
The [complete readback and per-file hashes](native-readback/summary.json)
retain raw positive/negative outputs and every range-verification output.

The original proving resource guard was executed read-only and refused the local
host: its observed available memory was below the unchanged eight-GiB floor.
The remaining eleven stages were not executed. GitHub reads worked and the
connection was enabled, but tree writes did not return. A bounded 1,010-byte
blob write also returned no result after 20 seconds, and exact blob readback
was 404. No new branch, pull request or hosted continuation run is claimed.
No permission-denial result or automatic-review rejection was received.
