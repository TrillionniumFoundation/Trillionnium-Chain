# Fresh native FullLimb comparison on the retained frozen harness

Qualification: **HOLD_NO_GO**.

These observations were newly executed on the same desktop as the public
W1 STARK research run. The baseline source is the original standalone
full-W1 harness from source commit
`e70f13448aad715286fb8eb56fc802b09db643a3`, recovered from the prior evidence
bundle with SHA-256
`d0eb6c28d99a3f8aefb8b49364d77d582248deb5bbdf8391d63244d7cc79db57`.
Its source tree remains outside the candidate repository; no old protocol
or Node tree is restored by this evidence directory.

## Actual build identity and one retained metadata caveat

The new build used Rust 1.95.0, release, codegen-units=1, thin LTO and
`RUSTFLAGS=-C target-cpu=native`. It produced the binary SHA-256
`3a8f27ca81aa94c310a8c573940bdf0f2339e92c18c290d10ee26b44615f2688`.
The retained build log records the explicit flags before the successful
locked/offline build and the same binary hash afterward.

The unchanged frozen campaign script has a hardcoded `build_profile` text
containing **"default target CPU"**. That old descriptive string does not
reflect this invocation's explicit RUSTFLAGS override. The original campaign
JSON is preserved byte-for-byte; this companion record explains the
discrepancy instead of silently editing an observed file or claiming both
descriptions are simultaneously true.

## Scope of the measurements

The campaign made three fresh processes, each pinned to CPU 0, with 50
iterations for every one of five valid and six invalid fixtures across six
verification modes: 9,900 measured calls. Each valid case/mode has 150
warm-call samples. The ordinary native FullLimb comparator for the STARK
fixture is **`retained`**, with median 1,913,279 ns and observed p95
2,630,817 ns. The pooled five-fixture median is a different statistic.

Each raw `native-run-*.json` also records one prefix reconstruction per
valid fixture before the timed verifier loops. `parse + make_prefixes`
recomputes the noise, E/F and full noisy-product prefix from an already
existing raw candidate. It does not generate the raw candidate's original
C/header/trace/ticket or search for a winning nonce. These three preparation
samples are not a stable tail-latency distribution or a cheapest-producer
lower bound. Their raw file hashes are pinned in `native-campaign.json`.

The fresh 143 library tests and the fixture conformance audit are separate
from the measured-call counts. This is not a production Node execution,
network campaign or current-C4 whole-crate build. The 41-file comparison
finds 39 equal files, one changed `legal_attempt.rs`, and one frozen
`legal_attempt/low_rank.rs` missing from C4. The ordinary FullLimb entry
`src/pon_work.rs` itself matches C4 exactly; the detailed source comparison
is retained alongside the raw results.
