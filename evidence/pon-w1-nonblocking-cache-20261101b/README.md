# W1 nonblocking rejection reuse and current Host checks

This continues PR #675 at exact base
`9cd91ed69a0c69df42f8d7812d32d271df6e1998` / tree
`60a521c7299febfe26a8c7d38d3420d490d07cd8`. The
[manifest](manifest.json) records the actual candidate input blobs, executed
binary hashes, original logs and scope. Tests ran on the listed uncommitted
candidate bytes; publication does not turn the base commit into tested source.

The optional exact rejection cache previously waited on its slot mutex before
the next cancellation callback or after full replay. `try_lock` now makes
contention/poison a miss or skipped publication. Three new native controls hold
the actual mutex while checking complete callback/result equality for invalid
and valid W1, cancellation at four boundaries, and an intentionally poisoned
cache. The held-lock worker must complete before the guard is released; timeout
cleanup releases the guard before joining, so a blocking regression fails rather
than hanging the suite. The ordinary cache remains opt-in.

The Host checker removes two temporary allocations per applicable check and
retains every actual file reopen, bound, refusal and callback. New controls
preserve strict token cardinality and slash-delimited parent membership.

| Executed check | Result and scope |
| --- | --- |
| Crypto default lib, locked original workspace graph | 119 passed; includes the 7 rejection-cache tests |
| Actual Host/error source in scoped harness | 19 passed; original dependency versions retained; not a full Node build or physical Host qualification |
| Initial Host harness | 18 passed / 1 failed: a new test incorrectly refused Unicode at numeric token edges; corrected test only |
| Formatting | Passed |
| CI contract / source negatives / PQ-source negatives | 95 / 34 / 34 passed |
| V2 legal reader / native-campaign runner / query model | 11 / 5 / 21 passed; these are software controls, not new cost measurements |
| All-target/all-feature Clippy for crypto/protocol/node | Blocked by actual `No space left on device (os error 28)` during crypto metadata output; no Clippy pass |

The intentionally caught poison-thread panic is part of a passing negative
control. The mistyped nonexistent runner command is retained as a failed
non-test attempt and contributes no pass count. Initial Host failure and Clippy
stderr are preserved verbatim in `logs`.

Canonical complete-Node reproduction remains:

```sh
cargo +1.95.0 test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-crypto-primitives --lib -- --show-output --test-threads=1
cargo +1.95.0 test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib host_kernel_parent:: -- --show-output --test-threads=1
cargo +1.95.0 clippy --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-crypto-primitives -p trnm-protocol -p trnm-pon-node --all-targets --all-features -- -D warnings
```

The all-feature command requires the repository-pinned OpenSSL provider. The
retained local harness includes the actual Host and error modules and actual
transport dependency. Its absolute paths identify the original execution;
replace the workspace prefix when reproducing elsewhere. It does not substitute
for the complete Node command or hosted head/prospective-merge execution.

The original four-second, sixteen-producer, six-depth service campaign was not
rerun locally. Its prior source-specific failures remain failed. No measured
service improvement, cheapest-work lower bound, quantum cost security, model
utility or production activation is established by this bundle.
