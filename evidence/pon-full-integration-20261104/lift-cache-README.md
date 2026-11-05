# Bounded account lift cache: measured source change

This package records a cache-only production change against Chain `6f458c4fbf07a0a44d7d7a6f451aa960c1b0a029`. It does not close the original hardware/attack/deadline business confirmation gate or the touched-state complexity gate.

## Source and behavior

Baseline commit `3e75f75f6afe9c34989530493826b8e33d339ed0` adds only the retained diagnostic to the original clear-at-8192 implementation. Candidate commit `04ed0f37e082061499efa30af7e262a15d67cb38` replaces that policy with 1024 buckets of eight fixed slots. Every hit compares the complete `(path, digest, source depth, requested depth)` tuple. At a full bucket, one slot is replaced using a deterministic sampler; a collision recomputes the original lift. No authorization, SQL, progress, graph/state verification, commitment, signing, or recovery decision is cached or skipped.

The lift slab is allocated on the first nonidentity lift and is bounded to 983,080 software-charged bytes per instance on this platform. The separate existing node decode cache is unchanged. Small graphs can use more cache memory than the former partially filled BTreeMap. Predictable malicious bucket collisions can reduce hits; no security cost bound may assume a cache hit.

## Method

Each arm executes five actual complete native account-graph cases: 1024, 9216, and 32768 accounts from empty arithmetic caches, then 1024 and 9216 after both caches have been filled with 8192 unrelated exact mathematical keys. The latter prefill is a synthetic cache-pressure state followed by the real graph, not an authenticated history campaign. Two independent caches remain live together. Each case has two cold-cache traversals and 100 warm traversals; instance order alternates. Every traversal checks the original complete graph/state semantics and asserts fresh SQL reads = progress callbacks = 2N-1, with the same root as the uncached oracle. All 510 traversals in each arm satisfy these assertions and the 8192-entry bound.

SQLite is in memory. Cold means new arithmetic/decode caches after seeding and an uncached oracle pass, not cold physical storage or process startup. Timings include actual SQL reads and parsing, but exclude Host quota checks, PQ authorization, complete State commitment, networking, and business confirmation. Baseline ran before candidate, not randomized crossover. The 100 warm samples and p99 are descriptive repeated observations, not independent deployment trials. Both arms use the same generic-sha2 dependencies from6f; the root agent's Linux SHA2 backend change is not included here.

## Warm traversal observations (milliseconds)

| Accounts | Unrelated prefill | Baseline p50 | Candidate p50 | Baseline p99 | Candidate p99 | p50 reduction |
| ---: | :---: | ---: | ---: | ---: | ---: | ---: |
| 1024 | no | 6.148140 | 5.879404 | 8.117856 | 7.266139 | 4.37% |
| 9216 | no | 422.658438 | 245.134870 | 521.235804 | 299.723802 | 42.00% |
| 32768 | no | 1582.465392 | 1468.463374 | 1827.871696 | 1678.709691 | 7.20% |
| 1024 | yes | 7.390949 | 6.053775 | 14.571825 | 9.936652 | 18.09% |
| 9216 | yes | 433.126833 | 243.816893 | 513.848361 | 319.352939 | 43.71% |

All cold samples, maxima, per-traversal roots/counts, and whole-process RSS/HWM are in the retained JSON. RSS/HWM includes allocator retention between cases and must not be interpreted as cache-only memory. On the 1024 empty-cache case, whole-process RSS was 22,152 KiB baseline and 22,668 KiB candidate; on the 32768 case it was 73,992 KiB baseline and 70,528 KiB candidate (candidate HWM70,744 KiB).

## Validation and remaining integration gate

The exact candidate binary passes 31 account archive tests and 90 native authenticated storage tests, with zero failures. Seven and one explicit diagnostics respectively remain ignored by the normal suite; the new510-traversal diagnostic was separately run and passed. Exact final source also passed strict all-targets Clippy, formatting, locked offline Cargo metadata,34 source-integrity negative tests and38 evidence-source negative tests. Raw committed-source identity verifies8026 tracked entries against candidate commit04ed0f37e082061499efa30af7e262a15d67cb38.

The full repository checker correctly rejects the old inline source pin in `.github/workflows/pon-branch-encoding-acceptance.yml:53`: expected old blob `d137e38fc08738f4e6d6b81712f7c7423624a8c2`, observed candidate blob `add62202c8038776d0db254c066c619dd8fe4620`. The parent agent owns that final integration pin update. This failure is retained, not suppressed or labeled passed.

## Reproduction

Use the recorded Rust1.95.0 toolchain, pinned OpenSSL3.5.9 native provider, locked6f dependency graph, and a fresh output filename. Build each recorded commit in an isolated checkout. The inherited test profile compiles the node at opt-level3 with debug assertions enabled; this is not a release business benchmark.

```sh
TRNM_NATIVE_LIFT_COST_OUTPUT=/absolute/fresh-observations.jsonl \
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --features pq-native-openssl --lib \
  native_lift_cache_complete_graph_cost_observation -- --ignored --test-threads=1
```

`compare_lift_cache.py` reads the two retained raw files, refuses incomplete sample sets, verifies roots/read/progress/capacity invariants, and generates the comparison. The compact archive excludes the412MB test executables; `manifest.json` records their exact retained paths, byte counts, and SHA256 values.
