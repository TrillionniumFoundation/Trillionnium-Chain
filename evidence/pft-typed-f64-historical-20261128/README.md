# One fixed historical typed-f64 observation

The unchanged Rust core consumed the already retained `n8-s17011` PFT weights
and original shard0 local feature rows 0..3. All 96 output bytes matched the
previous Python reference output: SHA-256
`a254e8385df48372e9cc35ef307521976c3eca5f77e7c65b503018a626364285`.
This establishes one observed correspondence, not all-input equivalence of the
new exact-sum profile with `math.fsum`.

[prepare_inputs.py](prepare_inputs.py) is the exact one-time preparation script.
It rechecks the separately retained candidate, feature-packet, expectation and
old receipt SHA pins, uses the existing strict candidate reader, and exports
the original dense little-endian binary64 bytes. The expected model and feature
byte copies originate from those same checked packets: they are comparison
inputs, not independent origin attestations. It does not execute matrix products.

[native_launcher.py](native_launcher.py) records the bounded first native run.
It retains source hashes before compiling and invokes the fixed
[historical_harness.rs](historical_harness.rs), which compares every output byte
with the already retained reference before writing the private binary output.
The launcher formatted the harness before freezing its executed source hash;
the core stayed byte-identical to the first 11 standalone controls. The raw
96-byte output, weights and feature arrays are deliberately absent here.

[OBSERVATION.json](OBSERVATION.json) retains the first native exits, all pins,
shape, source/input stability, and explicit false authority and quality claims.
The original receipt SHA is retained separately from this public JSON encoding.
Compilation and the one observation succeeded on the first attempt with
`rustc 1.95.0`, Linux x86-64, `-D warnings`; every stderr was empty.
The 120-second bound is an engineering process deadline. The observed process
duration includes startup and output comparison and is not a performance study.

No labels, DEV or final data were read; no normal-equation verification,
training, feature execution or model selection was repeated. There is no new
user B, original-owner authorization, native adoption, FinalUse, benefit,
payment or consensus claim. The full native crate still requires its own CI.
These scripts describe the exact retained private observation; their temporary
paths and private inputs are prerequisites, not a public deployment interface.
