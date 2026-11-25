# Witness completion and current W1 binding repair

Base: `6b851bc64db9d87db1bae083654902846f14c275`. Twenty source paths are changed. Native and security
qualification remains pending or HOLD as documented in `source-review.json`.

The metadata record contains four original attempts with three retained FAIL
results and one final continuation. The final continuation executes 51 named
controls and ten source reports; earlier successes retain their own source
snapshots. The cumulative wall cost is 11.07193668999389 seconds under the original
30-second engineering cap. See `engineering-readback.json` for exact costs,
named controls, errors, no-skip checks, report checks and final 350-input binding.

`retained-records.json` stores exact raw plans, runners, root launch reviews,
results, logs and original source bytes in one compressed JSON record set.
Its visible member manifest records every original byte count and SHA-256.
To inspect the set, decode the envelope `content` with strict base64, verify
`compressed_bytes` and `compressed_sha256`, decompress XZ with `lzma`, and verify
`uncompressed_bytes` and `uncompressed_sha256` before parsing that UTF-8 JSON.
For each inner item, encode its `content` as UTF-8 and verify `bytes` and
`sha256` against both the inner item and the visible member manifest. No
record is executed by decoding the envelope. Original CI ZIPs remain at their
recorded original artifact identities and hashes; they are not duplicated here.

The first result stays FAIL even though its 82 named tests actually passed:
the frozen expected roster misattributed inherited methods. The next two FAIL
results retain two real profile control errors and one module loader error.
The successful observations across snapshots do not certify all 290 controls
on this final source. Normal exact-source CI is still required for that claim.

The original four-second confirmation and 250 ms Witness limits, frozen V1
inputs, affected-upstream withdrawal, all unknown security/cost bounds and
original E1–E6 accounting remain unchanged. No production or consensus
authority is conferred by this engineering record.
