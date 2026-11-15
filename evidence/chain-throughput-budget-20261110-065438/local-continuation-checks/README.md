# Actual local production-library checks

The earlier ordinary-pool candidate passed exact Rust 1.95 `cargo check --offline --locked -j1 --lib` in 110.010459 seconds. Its `store/mempool.rs` checkpoint scope was subsequently narrowed; that earlier pass retains its original source hashes and is not a pass for the later tree.

The frozen combined History/pool implementation passed the same production-library typecheck in 19.734575 seconds with unchanged source-before/source-after hashes and no profile overrides. The source bytes were subsequently published as implementation `85a905b9e47cea0d76144253abb4a483b58bc2be`. This observation compiled the production library only: it did not compile cfg(test) or execute any native test. Full command, exact compiler identity, all runtime input hashes and original stdout/stderr remain in `frozen-lib-check/`.

Both observations are distinct from the five earlier unsuccessful native preparation attempts retained elsewhere. None is a measured TPS or complete-confirmation result.
