# Actual W1 trace mismatch and frozen witness continuation v2

The previous continuation's same-trace condition failed on real SDK output.
V2 preserves the original witness chain. It does not weaken the old check or
claim that the new local source controls are a complete proof.

## Fixed original material and failed v1 observation

Original source `5d957878ea82b09b555c713976f5157fde1089a0`, run `40511022475`,
job `122212651078`, artifact `12743386213`, and all 315 raw archive members
remain in [the original evidence](../pon-w1-session-continuation-20261027/README.md).
That actual attempt proved only 0–25 of 62 po2-18 segments; no complete receipt
existed. Its 3,500.259693808 seconds wall and 13,893.369769 seconds combined
user/system CPU remain a failed observation.

V1 continuation run `40606062524`, source
`8a99968115d76069dc4cc49607929f42d183ad1b`, failed shards 0 and 1 at the
fresh-session exact-byte guard. Shard jobs were `122545909074` and
`122545909018`. Their artifacts were `12782030083` and `12780723275`, with
SHA-256 respectively:

- `b0fe2ef6af3743d722675c4099bd445e6421f35052b0ca4b6ad0ad355bf1a1e9`;
- `6aba9bf146992d734e0b91183ca9a043e149ccff976a1611fc45070eff932e67`.

Both original job logs and every non-original `.log` member of both artifacts
are retained under `v1-shard0-logs` and `v1-shard1-logs`. Original-attempt logs
are already retained in its immutable complete ZIP. Process/resource/attempt
records are retained separately. No completed new segment is hidden by this
source correction.

## Proven mechanism

[trace-differences.json](trace-differences.json) compares every field after a
bounded complete decode of all 62 original and 62 fresh witnesses. Every byte
was consumed. The fresh raw witness files remain byte-exact in `fresh-session`
and are indexed by [fresh-session-index.json](fresh-session-index.json).

[original-guest-symbols.log](original-guest-symbols.log) places
`risc0_zkvm::guest::env::MEMORY_IMAGE_ENTROPY` at `0x223b00`, size 16. That is
memory page 2190, offset 768, the exact differing cell. The original read is
`69926f804ae3f60aeefeb994005f2ffc`; fresh shard 0 reads
`b926aa81aecabcad2877256e53b52c9a`. The first ordered host read changes; all
other reads and writes retain their order and values. Memory ancestry digests
and segment pre/post roots consequently change, while the final journal and
halted full session claim match.

The 16 upstream files in [upstream-sources.json](upstream-sources.json) match
Git blobs at fixed SDK commit `1cc70cf05033a79ebc90f07c679cb4bd1cd301b9`.
They show startup calling guest `env::init` before main, `sys_rand` filling
this named four-word static, `SYS_RANDOM` routing to host `rand::fill`, and
ordered host-read recording. SDK memory maps are ordered BTree structures.
No serialization-order hypothesis is used in v2 acceptance.

## Correction and verification

[CONTINUATION_V2.md](../../trillionnium/crates/trnm-crypto-primitives/guests/w1-risc0/CONTINUATION_V2.md)
explains the fixed witness source, native receipt binding, unchanged full
verifier, proof budgets and cost scopes. V1 is retained and still refuses the
actual different fresh trace.

The legacy 37 controls pass. The 16 new controls pass on the actual frozen and
fresh artifacts, covering witness/input/session substitution, byte mutation,
missing/reordered/duplicated segments, equal-length input replacement during
report readback, modified actual receipt bytes, a rehashed splice with a broken memory
boundary, malformed codec lengths, trailing data and policy relaxation.
The initial helper `cargo check` passed after correcting its Digest decoder.
Two later hardening changes (descriptor metadata checks and explicit zero PoVW
nonce enforcement) have not been rechecked locally yet. Final whole-backend
formatting passed. The real release build stopped at the declared 700 MiB
free-disk floor after 451.179 seconds; its actual exit was SIGTERM. Consequently
the local actual-26 STARK verification, native negative controls and strict
Clippy remain **NOT_RUN**. No positive cryptographic result is inferred from
Python or prior-revision Cargo checks. The isolated draft workflow must pass
these actual native gates before either missing-segment proving shard starts.
[local-scope.json](local-scope.json) records exact source hashes and this limit.
The first offline dependency miss, first Rust `FromStr` compile error and
first raw-root-versus-tagged-image parser observation remain retained.

Local proof resource admission refused the available-memory requirement. No
local prover was started and no resource gate was reduced. The new workflow
must still produce the 36 missing real segment proofs, bind all 62 receipts,
verify the complete original statement, run the original hostile-proof audit,
and measure actual loopback transfer before full prototype acceptance.

The reports count repeated export/original receipt verification in each shard
and keep the original timeout and both v1 failures visible. A continued proof
is not a from-zero complete-proof performance result. Maximum tested invalid
input cost is not a global worst-case proof; loopback is not a WAN experiment.
