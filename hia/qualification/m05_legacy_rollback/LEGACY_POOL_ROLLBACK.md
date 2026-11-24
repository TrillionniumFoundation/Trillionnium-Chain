# Optional legacy owner pre-COMMIT rollback check

This is an isolated original-Rust test, not a CI gate or an HIA owner switch.
It runs a signed **legacy** task-owner fixture with two fresh development
databases. The test-only SQLite update observer advances the existing owner
epoch after SQLite inserts the real metadata row. It issues no SQL and returns
no simulated commit or error. The original post-INSERT permit check must give
`OWNER_TASK_VIEW_CHANGED`, with no commit and one SQLite rollback notification.
The matching control keeps its row on commit. The already-reserved owner claim
stays recorded in both scenarios.

After closing the original Node, an independent read-only SQLite connection
checks the table rows and exact stored context/limits BLOBs. A fresh development
Node separately checks the status, active parent/generation and state. This is
not a protected deployment reopen, a full policy refresh, continuous/PQ
authorization, a crash test, or the hosted Node/M05 oracle.

## Prepare from original Git bytes

Run from the repository with a fresh location **outside** the checkout. The
preparer verifies each archive input against the exact commit's Git tree and
splices the adapter only into the private copy of the pre-existing Rust test
module. It writes the source binding and exact filter to `preparation.json`;
preparation is not test execution.

```sh
python3 -B hia/qualification/m05_legacy_rollback/legacy_pool_rollback.py prepare \
  --source <exact-original-commit> --output <fresh-isolated-preparation>
```

Use the existing original Node recipe's absolute pinned Rust/Cargo and
loader admission rule in [rust_oracle.py](../../platform/mempool_node/rust_oracle.py). Reject external
tool/loader overrides before deriving `<rustc-sysroot>/lib`; use locked
dependencies and a fresh Cargo target. Build with
`cargo test --locked --manifest-path <preparation>/source/trillionnium/Cargo.toml
-p trnm-pon-node --lib --no-run --message-format=json --target-dir <fresh-target>`.
Require the actual SQLite layout witness and bind the emitted unit binary's
digest. Run only the exact `rust_test_filter` followed by
`--exact --test-threads=1 --nocapture`; save the raw logs. Keep the repository
profile intact for any canonical optimized evidence.

On original source `e3c4d55cffcd2bb389227b585c67e1a79c52dc7f`, the local
default optimized Node test build (`opt-level=3`) ended in external SIGKILL;
no test executed from that attempt. Locked Rust 1.95.0 built and executed the
same fixture with a **local diagnostic** CLI override
`--config profile.test.package.trnm-pon-node.opt-level=0`. Debug assertions,
overflow checks, production source and CI configuration were unchanged. The
diagnostic passed both matched cases and an exact repeat. It does not close
the canonical optimized or continuous-owner gates.

## Read back or replay that retained diagnostic

Keep the original `verified-receipt.json`, the named test's raw stdout,
`independent-repeat.stdout`, and for replay the archived
`local-qualification-unit-test.gz` together. Supply receipt and repeated-log
digests from the separate pinned evidence manifest, not from an untrusted
archive. The reader checks both raw event pairs and the receipt's explicit
scope. Replay additionally verifies the executable before running the same
synthetic inputs. It is neither a new Cargo build nor a hosted acceptance run.

```sh
python3 -B hia/qualification/m05_legacy_rollback/legacy_pool_rollback.py readback \
  --archive <retained-archive> --receipt-sha256 <receipt-digest> \
  --repeat-sha256 <repeat-stdout-digest>
# Replace readback with replay and append --output <fresh-disjoint-directory>
# to execute the admitted retained unit binary.
```
