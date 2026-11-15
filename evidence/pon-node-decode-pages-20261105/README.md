# Bounded lazy pages for exact node decoding

The decode arithmetic cache now allocates fixed eight-slot pages on demand instead of allocating all 8,192 slots after the first valid decode. Its logical slot index, eight-probe limit, first-empty stop, collision refusal, exact current-byte/ID binding, original-decoder errors and two independent borrow attempts remain unchanged. Every SQL read and graph check stays in place. No apply-cache shortcut is introduced.

## Verified scope

Local implementation source: `1a9832032158779d1957795e1421470b16d1b665`, based on `03521b2f32346a49cccde8ff72e8c7b886b31222`. Final local source registration and validation: `0f443366feca2bd300932dc1d69c0c00b90ff55f`, tree `02be2acdaf68602a96dbce627dd334f4008cf027`. The retained source patch reconstructs that validation tree from the published base. The delivery adds only this evidence after that source.

With original Rust 1.95.0 profiles, locked packages and default features, **115 distinct native tests pass**: the complete account-store selector has 23 passed/four existing ignored; the native-authenticated selector has 92 passed/one existing ignored. The ten decode controls are a subset, not an extra denominator. They include an independent frozen eager algorithm, genuine colliding content hashes, cross-page/wrap probes, invalid inputs, borrow conflicts, partial allocation and full software-charge accounting. Existing SQL freshness, cancellation and reopen controls also pass.

Strict workspace/all-target/all-feature Clippy, formatting, 37 source controls, 100 CI-contract controls, all 522 source pins and unchanged generated inventory pass. The locked graph remains 26 workspace members and 175 packages. Clippy does not constitute all-feature runtime or PQ-provider qualification.

## Memory accounting and limitations

On the actual 64-bit test layout, one allocated page charges **11,528 bytes** including the directory and owner. The three-entry/two-page fixture charges **14,792 bytes**, compared with the eager representation's full-table software charge of **3,342,408 bytes**. These are software-accounted allocations, not RSS measurements.

The fully allocated derived maximum increases by the **8,192-byte directory**, to **3,350,600 bytes**. The independent **4,194,304-byte hard ceiling is unchanged** and checked at compile time. Observation schema v2 records logical capacity separately from allocated pages, directory bytes and owner bytes. Invalid records, exact hits, full-probe refusals and borrow conflicts do not allocate additional pages.

The synthetic full-table fixture checks accounting and refusal in private storage; it is not an executed 8,192-node valid SQL graph. Allocator metadata, fragmentation, SQLite and other caches remain excluded from this software charge. More small allocations can affect dense-workload cost. Runtime nonregression, process RSS, complete publish latency and the original four-second hostile-W1 gate are **not measured or qualified by this change**.

[Exact records and per-file hashes](verification.json) bind the [complete raw validation logs](raw-validation.zip). The first parallel diagnostic output is retained despite interleaving; a serial replay preserves complete observation JSON. The prior rejected apply optimization remains separate and withdrawn.

Reproduce the native selectors with `cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib account_archive_prototype::native_store:: -- --nocapture --test-threads=1` and the same command selecting `store::native_authenticated::`. Original ignored acceptance fixtures remain required in their own declared gates.
