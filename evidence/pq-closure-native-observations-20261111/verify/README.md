# Offline desktop evidence verifiers

These scripts verify retained records without running native workloads, Cargo,
Python test suites, H jobs, or network requests. A successful verifier exit means
that the checked packet is internally consistent with the fixed source and
recording contracts. The result separately reports whether the recorded workload
passed. Failed or timed-out runs remain failed even when their evidence verifies.

## Fixed inputs

Keep these four files together when moving the verifiers:

- `verify_desktop_native.py`: original C1 verifier, pinned SHA256
  `02b62d0a6b206ba35fb6c66e85b3a46bdfc2c03ea9a348771eef29b3cb5aae4c`.
- `expected-native-plan-c09dbbe992.json`: independently derived C1 plan, pinned
  SHA256 `f83cfaa68c52e9e05e0576158ba5170635482168bb7ee5090d4bc5d158713d2c`.
- `verify_desktop_subsets.py`: shared verifier for the readback and witness V5
  subsets; the C2 verifier pins its complete bytes.
- `verify_desktop_c2.py`: exact C2 packet verifier.

The generic exporter was statically compared at SHA256
`9819d3733f6239c66e23f7567b9a7363294be058d912daff5176e1c0fb09c014`.
Its subset/C2 archive receipts have schema `trnm-observation-archive-receipt-v1`;
the manifest schema is `trnm-observation-raw-export-v1`. Original C1 export
schemas remain unchanged. The raw exporter status fields use `summary.get`, so
the subset's absent `complete` field is retained as null; it does not become an
aggregate pass.

## C1 subset verification

For either `readback` or `witness-v5`, supply the corresponding subset archive
and receipt, plus the original native archive and receipt:

```sh
python3 -I -B verify_desktop_subsets.py \
  --kind readback \
  --archive /absolute/path/readback-subset.tar.xz \
  --receipt /absolute/path/readback-subset-export-receipt.json \
  --original-archive /absolute/path/original-native.tar.xz \
  --original-receipt /absolute/path/original-native-export-receipt.json \
  --git-source /absolute/path/repository-with-C1-objects \
  --output /absolute/path/new-readback-verification.json
```

Use `--kind witness-v5` and that packet's files for the second subset. Each
invocation first calls the fixed original verifier as an isolated, read-only
Python subprocess. It then checks the actual original summary, failure receipt,
stdout, stderr, complete source snapshots, and provider snapshots against the
subset references and original archive bytes.

The readback subset skips exactly four originally completed names and selects
the remaining ten. Witness V5 skips exactly six and selects eleven. Both use the
original 1,200-second limit and one test thread. The verifier checks actual
listing and run output, exact names, no ignored/measured cases for a pass, raw
log hashes, exit/timeout state, executable observations, and retained descriptor
binding metadata. Partial `ok` lines remain separate from complete target passes.
The original two group timeouts remain failures regardless of a subset result.

The ELF executable itself is not in these packets. Its expected SHA256, size,
path, descriptor binding, and after-command hash are recorded observations; the
offline verifier does not rehash the absent ELF or attest execution on the host.

## C2 verification

```sh
python3 -I -B verify_desktop_c2.py \
  --archive /absolute/path/c2-native.tar.xz \
  --receipt /absolute/path/c2-native-export-receipt.json \
  --original-archive /absolute/path/original-native.tar.xz \
  --original-receipt /absolute/path/original-native-export-receipt.json \
  --readback-archive /absolute/path/readback-subset.tar.xz \
  --readback-receipt /absolute/path/readback-subset-export-receipt.json \
  --witness-v5-archive /absolute/path/witness-v5-subset.tar.xz \
  --witness-v5-receipt /absolute/path/witness-v5-subset-export-receipt.json \
  --git-source /absolute/path/repository-with-C1-objects \
  --output /absolute/path/new-c2-verification.json
```

C2 is exactly `0e554f36ffdde3053a5eb1756eb5e526b1935032`, tree
`753cdbad6714f00d8ccb9ddbb47f0fd71280ee62`. The verifier independently fixes the
14-command plan, eight native executions, and strict workspace Clippy argv and
budgets. Metadata, version, native output, and receipt pass/fail fields must
agree. Missing later invocations and failed/timeout results remain visible.

The complete C2 snapshots contain 27,912 tracked entries and 2,554,108,569 bytes.
Their rows must equal the original C1 snapshot except for three exact Git blob
changes: the readiness checker, its tests, and the corpus JSON containing two
changed pins. The net difference is 1,880 bytes. No Rust source or Cargo lock
change is inferred. All three prior C1 summaries and their actual archived bytes
are cross-bound. Provider bytes remain identical across groups.

The private Cargo target was reused from the closed C1 group. This is not a clean
build assertion. With `--git-source`, the original C1 verifier recomputes every
C1 Git blob hash with lazy fetch and replacements disabled; the C2 verifier then
binds the exact three independently pinned C2 deltas. Without that option, the
result explicitly leaves full original Git recomputation null and checks the
retained source records and fixed deltas only. No network fetch is performed.

Both commands create `--output` exclusively and refuse to overwrite it. Omitting
the option prints the result. Counts are execution observations, not independent
security-property counts. No result changes hosted CI, the failed original C1
aggregate budget, production activation, or whole-chain PQ qualification.

## Review status

The scripts have been statically compared with their fixed recording/export
sources and parsed with Python AST. At this preparation step, the subset and C2
archives are not yet available for end-to-end verification. This document does
not claim that any such archive has passed the verifier. Actual invocation
receipts must be recorded separately once those packets exist.
