# Initial-root ordinary CI: run 41748875721

## Result and exact scope

Independent inspection of the four original official artifacts verified **304 actual named native passes, 0 failures, 0 ignored, 0 measured**. Each lane has **76 = Node 46 + M06 18 + protocol 8 + original CPU 2 + lifetime 2**. Node 46 retains the former 39 and adds seven initial-root controls. Registry listings, build success, and the ignored parser observation are not counted as native passes. Three CPU backend observations within two tests are not three additional tests.

Run: https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41748875721
Event: push; attempt: 1; terminal conclusion: success.

| Lane | Job | Artifact | Original ZIP bytes | Official ZIP SHA256 |
| --- | --- | --- | ---: | --- |
| ubuntu-24.04 / head | 126308679902 | 13285312643 | 302305 | db3c36eeb85f3d25d4c3c265c12e5c19233722388d25126fc1970d4ee6da40a0 |
| ubuntu-24.04 / prospective-merge | 126308679928 | 13285398555 | 302532 | 0ed10048afd1a9eb5a6c985972f544e31f78318d3d98b92f290913e6b68b708a |
| ubuntu-24.04-arm / head | 126308679850 | 13285472881 | 302055 | 528fdcd6627a7d73fdc5c9e6a8a0a0346bd34e27bf1071eb7542a60ebb800ca4 |
| ubuntu-24.04-arm / prospective-merge | 126308679673 | 13285614471 | 302200 | 0723ed3296af00718bc2d84f7575a3adbb75be11aefa49c170814c2f561a5e61 |

## Source and build

- H: `4c46eca89a006616e9240d983c66919071f79b41`
- Actual prospective merge M: `e0f831d0af21cc9eea69b5ec84788ef66e0b025c`
- Base B: `2e72a989d001cf51bd0aed0e1401526e45db31f1`
- Both tested source trees: `a32c5e3b169370b1c923bb9a6ef7094a3d3ef041`
- M ordered parents: B, H.
- Separate normal harness S: `01404de030c0d560e32a4b86620cea027878d2df`, direct child of H; its only delta adds the reviewed workflow.
- Workflow SHA256: `af6f66151bba9dc3d7d58218b2dbf84b570e75cd2acc2eec86b165200f8d5983`.

All original source-before/source-after pairs agree, with 6,862 tracked entries and 784,979,280 tracked bytes. The harness is separate from the product source actually tested.

The original build is `cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features --no-run --message-format=json`. This produces Cargo `build.jsonl` compiler-artifact records, not a Bazel BEP. Node uses optimization level 3, M06 level 1, both with default + pq-native-openssl; protocol uses level 3 and no crate features. Debug assertions and overflow checks remain enabled. All three test executables in each lane come from that same original workspace build. Actual resource commands retain the original package directory, exact ELF, selector, --exact, --nocapture, and --test-threads=1.

The ZIPs contain no executables. These records establish CI-recorded ELF hashes before/after each lane, tied to Cargo artifacts; they do not establish an independent rehash of downloaded binary bytes. Different lanes can have different Node ELF hashes.

## Original CPU accounting

Every CPU observation has outer dispatch and inner native Ok. Burst remains 2,000,000,000 ns; refill 250,000,000 ns per second; start reserve 100,000,000 ns; worker limit 2. Owner plus worker CPU, live plus residual CPU, and settled paid debit all agree. Every final credit is positive, with no outstanding owner.

Each Authenticated observation completes 11 complete-commitment calls, reuses three initial roots and two full roots, performs 25 actual root calculations and 29,534 new row hashes, and compares 23,145 rows in 11 projections. Reuse/comparison is not counted as new hashing. Nested stage times must not be added.

The aggregate original audit preserves every paid/refill/credit observation. The portable reader adds an explicit consistency guard requested in independent review: all **12** original samples must have both `before.initial_credit_ns` and `after.initial_credit_ns` equal to exactly 2,000,000,000. This is a data-only supplement; the original reader and its result remain byte-for-byte unchanged.

## Lossless contents and offline verification

`index.json` describes four original ZIPs split into JSON/base64 chunks. Each complete chunk file is at most 48 KiB; each raw slice is at most 32 KiB. Exact offsets, raw/encoded sizes, SHA256, and Git blob identities are retained. Reassembly is lossless and must match the official ZIP digest. No ZIP member is extracted or executed.

Run the authored outer data reader from this directory:

```text
python3 verify_payloads.py
```

It uses only the Python standard library, verifies all chunk and original ZIP identities, fully reads every member for CRC checks, checks source/harness/build/profile/feature/recorded ELF identities, verifies every original named native log, execution receipt, exact resource command and exit result, and independently verifies the CPU balances and initial credits. It performs **zero native test invocations and zero artifact-code executions**. It does not execute the archived original reader, workflow, or any ZIP content.

`audit_artifacts_v1.py` is the unchanged source of the original full Main audit. Its fixed original Main paths are retained as provenance; use the portable outer reader for this bundle. `audit-input-v1.json` retains official run/jobs and raw Git object responses. `FOUR_LANE_INDEPENDENT_AUDIT_V1.json`, `AUDIT_V1_COMPLETION_RECEIPT.json`, and original process status/stdout/stderr preserve that successful audit. Its four report paths identify the original detailed Main outputs; redundant derived reports are not repeated here because every original source log remains in the lossless ZIPs.

`READER_RESULT.json` and `READER_EXECUTION_RECEIPT.json` record the actual portable verification. `HANDOFF.json` lists the complete outer delivery by size, SHA256, and Git blob SHA. The handoff itself is not self-hashed. Place the relative files directly under `evidence/initial-root-ordinary-20261104/cloud-run-41748875721/`; no original source or older evidence is replaced.

## Boundaries

This closes the selected ordinary CPU, semantic and lifetime scope for H and actual M on x64 and ARM. It does not assert full runtime, V5 confirmation, DAG fixed-parent, pressure/campaign, whole-chain PQ or release qualification.

Local a09's two original CPU selectors separately passed once on the same source tree under the local default-feature build. They are not added to this cloud denominator or presented as the identical cloud binary/profile. Earlier 0878, ecb, b73 and rejected encoder failures remain valid archived observations. The 479-file local evidence package at parent archive commit `35f8e3419ae3c57d093f26870199806c347901d0` remains unchanged.
