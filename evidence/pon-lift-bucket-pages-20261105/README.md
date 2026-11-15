# Bounded lazy pages for exact lift arithmetic

Lift arithmetic now allocates eight-slot buckets on demand instead of eagerly allocating all 8,192 slots. Full input equality, bucket hashing, scan and overwrite order, retained count, the wrapping pseudo-random replacement sequence and borrow-conflict fallback remain unchanged. Every original graph, SQL and Host check remains in place. This is independent of the withdrawn apply-cache experiment and changes no generated source inventory.

## Exact validation

Base: `36c8effa32f004fdde30c139eab206af7f4fad8f`. Local implementation: `a8381f0181f110731837acf50c635a0aff8c7975`. Final local validated source: `bee753f411f9f1f0c6ba5f8dfcd15ee9c444c26c`, tree `372d5472a7efbbae3f782292c685bdfa47b2f4d5`. The raw ZIP includes the exact patch reconstructing the validation tree from the published base; delivery adds only evidence.

Original Rust 1.95.0 profiles and locked default-feature native tests: **119 distinct passes**, zero failures. Account-store selector: 27 passed/four existing ignored. Native-authenticated selector: 92 passed/one existing ignored. Four new paging tests and the 11-pass/two-ignored constants roster are subsets, not additional tests. The frozen eager oracle compares all slots, count and RNG; it checks exact input mismatches, overwrite/scan order, collisions, pinned replacement victims and integer wrapping. Identity and conflicting borrows retain the original fallback. Synthetic storage fixtures are not valid-lift mathematical or SQL-graph acceptance evidence.

The exact CI roster now requires all original seven controls plus all four new controls, retaining both ignored observations. Ten reader controls include rejection of the entire old seven-pass roster. The branch workflow keeps its complete selector and original gates. All 522 pins, unchanged inventory, 37 source controls, 100 CI controls, strict workspace/all-target/all-feature Clippy and formatting pass. All-feature Clippy is not PQ runtime qualification; local OpenSSL is 3.5.7, not 3.5.9.

## Allocation accounting and limits

The first allocated bucket charges **9,192 bytes** rather than the eager table's **983,080 bytes**. Full occupancy charges **991,272 bytes**, an 8,192-byte directory increase; the separate **1,048,576-byte hard software ceiling stays unchanged**. Tests exercise empty, partial and fully allocated storage. Charges exclude allocator metadata, temporary allocations, stacks, SQLite, compiled empty tables, decoders and other caches. They are not process RSS measurements. More small allocations may affect dense workloads; runtime nonregression is not measured.

This unit does **not** close the original four-second, at-least-16-hostile-W1 business gate or establish end-to-end latency. Original ignored gates remain required. See [verification and hashes](verification.json) and [raw logs and source patch](raw-validation.zip).

Reproduce with `cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib account_archive_prototype::native_store:: -- --nocapture --test-threads=1`, then the same command selecting `store::native_authenticated::`. The exact roster uses selector `account_archive_prototype::native_store::tests -- --show-output --test-threads=1` and `scripts/ci/check_native_constants_roster.py` on its complete transcript.
