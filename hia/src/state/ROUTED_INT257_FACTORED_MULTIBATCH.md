# Private same-call Int257 Factored multi-batch

This immutable local borrower validates the complete model and all three
factor/delta equalities once per call, then uses the genuine existing
selected-expert A×x and B×hidden arithmetic separately for up to four
mini-batches. No factor is cached across calls. No token, authorization,
public protocol, production selector, measured speed claim, or proof.

Input is the [same model and factors](ROUTED_INT257_FACTOR_PREPARATION.md)
40,460-byte prefix, LE32 mini-batch count, four LE32 row counts (unused
slots must be zero), then concatenated 257-coordinate signed LE32 rows.
There must be 1–4 mini-batches, at least one row in each and at most 64
rows overall. First validate outer shape, then model and factors, then
the independent feature/bias rows in original mini-batch order. The
aggregate size cap is an additional private framing constraint. No
features, scope or time are acquired externally.

Output has four LE64 segment byte lengths, unused slots zero, then one
unchanged [Factored result](ROUTED_INT257_FACTORED.md) per batch. All index
bins start from that batch's first row, never the call's first row.
Every input row and capacity check completes before scratch or output
writes. Results are computed in scratch, including actual hidden state,
before any result segment is published. Scratch requires 264 + 50×total
bytes. Output requires 32 + 88×batches + 51×total; maxima are
106,272 bytes input, 3,648 output and 3,464 scratch. Input and output tails
remain untouched. Bad shape (100), insufficient capacity (102), model
or factor errors and late ordinary batch errors do not publish earlier
results. An unexpected defensive numeric refusal (12) also does not
write output, although computation may have used scratch.

The standalone synthetic oracle on unchanged locked Rust genuinely calls
new and prepare_factors once, then prepare_batch and factored for each
mini-batch. Both stock HIA emitters compare complete segments, per-batch
counts/indices and late refusal atomics against it. The original
one-batch source, ABI and binaries remain unchanged.
