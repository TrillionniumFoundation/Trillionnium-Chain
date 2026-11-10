# PoN native journal boundaries and from-zero filter cost evidence

## Result and scope

This packet records two bounded changes on one fixed source: refuse FIFO replacements at two native journal read boundaries before a blocking open, and measure the cost of constructing a from-zero false transcript versus preliminary filtering and complete native rejection. It contains a successful fixed-source component experiment and the complete two affected native test suites. It does not qualify an open consensus network or activate production.

**Overall qualification remains HOLD / NO-GO.** Source and component execution are the new evidence. Real task demand, correct end-to-end delivery, independent model net benefit and an all-legal-strategy consensus work-cost bound remain separate obligations.

**Publication:** the [fixed source](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/39336622c63df1ae746d83a76bb53202cd01ba17) was published through the authenticated local GitHub channel and read back with its identical commit and tree. The initial native packet was delivered in evidence-only commit `42d6ab45598cbba3d476a3c558b7fce562f13877`. The later [integration binding recheck](INTEGRATION-RECHECK.md) preserves two additional inspector failures and the consistency repair on `be24e0be`; all native execution and quality receipts below retain their original source identity. Hosted CI is a separate observation and no hosted pass is claimed in this packet. The failed first quality commands and precommit negative controls remain intact.

The subsequent [combined-source recheck](COMPOSITION-RECHECK.md) records the ordinary merge with integration candidate `df927b6f`, fresh native and control execution on `f5e836c2`, and separately retained build failures and recoveries. It does not rerun or transfer this report's native cost measurements. The original archives and their execution identities remain unchanged.

## Fixed execution identity

| Identity | Observed value |
| --- | --- |
| Executed source commit | `39336622c63df1ae746d83a76bb53202cd01ba17` |
| Executed source tree | `42fbd7d5a7f00b75000cb4aa242e578a8f941d59` |
| Parent source | `da1374a200022bc14dc2bd325cc9ba29dbcd24ab` |
| Complete tracked entries | 27,663 |
| Complete tracked bytes | 2,527,920,394 |
| Before/after source observation | committed-clean; raw tracked bytes verified against the fixed commit |
| Cost example binary SHA-256 | `82b03a766f0a84055d1d96ab8f052bd6f8f89f23bee1f2f3eb2644fe9b115f00` |
| Native cost stream SHA-256 | `953ef816f391839d1bae8b7c3cb2c6653b2bfad2eb611968288167afcf2d3f7d` |
| Runtime | Rust 1.95.0; Linux x86_64; kernel 6.18.57 |
| Observed CPU | Intel Xeon Platinum 8573C; 9 logical CPUs |
| Initial evidence-only delivery | `42d6ab45598cbba3d476a3c558b7fce562f13877`; parent is the executed source above |
| Hosted execution | No hosted execution pass claimed at packaging |

The native source commit contains nine changed files: the two production read-boundary fixes, two affected test files, the new cost example and its runner/controls, the regenerated distributed source inventory and the existing sole development plan. No consensus work formula, target, difficulty adjustment, chainwork rule, signed domain or production activation flag was changed. Any later evidence-only child identifies delivery; it does not acquire a new execution claim from this source commit.

The source checks establish the bytes inspected before and after the recorded commands. They are not host attestation, independently authenticated clock measurements, or proof that a same-privilege writer could never change and restore bytes between observations.

## Native read-boundary repair

`native_owner_journal::read_packet_file` and `native_risk_ledger`'s native-prefix read already refused nonregular files after opening a no-follow descriptor. A FIFO with no writer could block in that open before the descriptor type refusal was reached. The repair adds `O_NONBLOCK` to the existing `O_NOFOLLOW | O_CLOEXEC` flags. Existing descriptor-bound type, length, identity and journal/risk checks remain in place.

This is a local filesystem substitution boundary: the reproducer replaces a cached packet or native-prefix file with a FIFO. It does not demonstrate that a remote peer, without filesystem write access, can perform that replacement. It does not supply a hard deadline for arbitrary regular-file/storage stalls.

The repaired controls require refusal without native admission or risk spending, preserve the relevant journal/bank observations, and retain owned child-process handling. Full affected suites also exercise earlier corruption, locking, pending-operation, checkpoint, restart and process-cut behavior.

### Preserved pre-fix controls

| Development control | Observed old behavior | Scope |
| --- | --- | --- |
| Cached packet replaced by FIFO | `read_started=true`, child exceeded its bounded observation window, child killed with SIGKILL, parent test failed | New test on a precommit local development snapshot |
| Native prefix replaced by FIFO | `read_started=true`, child exceeded its bounded observation window, child killed with SIGKILL, parent test failed | New test on a precommit local development snapshot |

The original files `journal_fifo_before.log`, `risk_fifo_before.log` and `journal_fifo_before-source.json` must be retained unchanged. The selected-source receipt explicitly says it is **not a clean committed-source qualification**. These observations are useful regressions against the old read behavior; they are not whole-source execution passes or failures assigned to the clean parent commit. The complete clean-source observations start at `39336622`.

### Complete affected suites on the fixed source

| Native harness | Top-level result |
| --- | --- |
| `native_owner_journal` | 11 passed; 0 failed; 2 ignored helper entrypoints |
| `native_risk_ledger` | 12 passed; 0 failed; 2 ignored helper entrypoints |
| Combined distinct top-level methods | **23 passed; 0 failed; 4 ignored helper entrypoints** |

The four top-level ignored entries are owned subprocess helpers invoked by their parent tests, including the new FIFO controls and existing process-cut controls. They are not added again to the 23-method denominator. `native-journal-suites.log` and its command receipt retain the original harness output and exit zero. This is complete execution of these two integration suites, not execution of every native library or every original public-service campaign.

## From-zero filter/rejection cost experiment

The fixed experiment has two public synthetic matrix recipes (`zero`, existing hash-generated/rank-checked `full-rank-field`), three targets, eight samples and two producer arms. This gives **96 construction samples**. Each winner has six observations: preliminary statement check, raw full verifier first/repeated call, fresh arithmetic cache cold/hot call, and independent scalar reference verifier: **576 stage observations**.

The target thresholds are exact `(2^256 / 2^b) - 1` for `b` in 1, 4, 8. The displayed `p=1/2^b` is the corresponding probability under a uniform ticket model. This finite deterministic experiment does not establish hash independence or a random-oracle security reduction.

The from-zero arm validates/serializes public A/B once per sample, initializes C to zero, then computes a candidate trace and ticket once per nonce until the first target hit or the fixed 4,096-attempt limit. It receives no valid proof input. The legal comparator is the existing full-limb producer with dense AB preparation and winner-only proof materialization. It is one explicit legal strategy, not a fastest legal miner. Legal and forged searches share material, target and sample identity; legal search changes the challenge while false-trace search changes the claimed trace at fixed challenge. Winners need not share the exact statement.

All completed misses, binary trial-buffer bookkeeping, per-sample setup and proof cloning remain inside their recorded algorithm intervals. Hex/JSON formatting and output occur after those intervals stop. Fixture generation, public task hashing, receiver-cache setup, raw records and the whole campaign interval are recorded separately. Retained observation-buffer cleanup belongs to the whole campaign, not the individual algorithm interval. A partial/exhausted/failed stream cannot be promoted to a successful complete campaign or treated as zero unfinished cost.

| Arm | All trials | Completed misses | Target hits |
| --- | ---: | ---: | ---: |
| From-zero false transcript | 3,814 | 3,766 | 48 |
| Explicit legal comparator | 7,528 | 7,480 | 48 |
| Total | 11,342 | 11,246 | 96 |

All 48 false candidates passed the preliminary statement check. Every subsequent full raw and independent scalar verification rejected them as `Transcript`. No false candidate gained a `VerifiedWork` value. The correct legal counterparts were accepted. The raw-first/raw-repeat labels describe invocation order, not controlled hardware cache temperature. Arithmetic-cold/hot refer to a new one-slot `ArithmeticFactCache` owner and exact-statement reuse.

### Six finite cost observations

Each row averages eight from-zero samples. CPU values are **microseconds per submitted candidate**. Construction includes per-sample setup plus every losing and winning search attempt; the preliminary and raw-full columns are separately executed calls. The ratio is the sum of their CPU costs divided by all construction CPU in the same eight samples.

| Input | Conditional p | All fake trials | Mean construction CPU (µs) | Mean precheck CPU (µs) | Mean full raw CPU (µs) | Mean precheck + raw CPU (µs) | CPU cost ratio |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| zero | 1/2 | 19 | 50.429 | 29.984 | 698.485 | 728.469 | 14.445546× |
| zero | 1/16 | 163 | 71.454 | 31.446 | 708.120 | 739.566 | 10.350190× |
| zero | 1/256 | 1882 | 151.091 | 31.734 | 723.023 | 754.757 | 4.995391× |
| full-rank-field | 1/2 | 10 | 78.425 | 47.951 | 820.208 | 868.160 | 11.069866× |
| full-rank-field | 1/16 | 132 | 50.373 | 42.794 | 749.588 | 792.382 | 15.730326× |
| full-rank-field | 1/256 | 1608 | 136.004 | 44.364 | 760.756 | 805.120 | 5.919810× |

These are observed component cost ratios on the named machine and fixed sample set. They are not confidence intervals, a worst-case amplification bound, proof of a monotone difficulty/cost relationship, or a measurement of admitted public-network requests. Public fixture/task setup is separate from the per-sample denominator. Both arms retain all fixed-seed outcomes; there is no winner-only denominator or reroll until a favorable result.

Verification clocks include their progress-count callbacks. Path order is fixed; producer arm order rotates by sample. The arithmetic cache is an opt-in mathematical component. Its hot result does not establish default listener behavior, paid admission, independent receiver behavior, restart accountability or a public-service speedup.

The native campaign interval ending immediately before its terminal record reported CPU **5.098216152 seconds**, wall **5.180605522 seconds**. Final-record formatting/output and function/process teardown are outside that interval. The nonoverlapping measured intervals total CPU **4.917893239 seconds**, wall **4.998588250 seconds**. The reader verifies these sums do not exceed the complete campaign interval. These totals include observations outside the six-row algorithm ratios; none is an energy, economic-cost or hardware-isolation certificate.

### Stream and input controls

The reader checks exact event/field schemas, fixed ordering/targets/identities, the public matrix recipes and product bytes, every false-trace trial and ticket, all preceding misses, first-hit selection, proof hashes, fresh/cache-hot replay boundaries, complete denominators and timing containment. It refuses omitted/duplicated/reordered events, inconsistent clocks, false outcome promotion, non-integer/nonfinite/duplicate-key JSON, and bounded-input violations including FIFO and symlink inputs.

**20/20 controls passed with the actual native stream; zero skips.** The test command ran under the same fixed-source before/after guard. Its raw test time was 7.400 seconds; its command receipt including guards records 21.365963414 seconds and exit zero. The native stream hash after these controls matches the execution receipt. These consistency checks do not independently authenticate native execution or the truth of physical clocks.

## Fixed-source validation and retained failures

| Recorded command/cohort | Terminal observation | Limit |
| --- | --- | --- |
| Cost runner preflight, Rust identity, release build and native experiment | Four command exits zero; runner PASS | Exact source/binary-bound component execution |
| Actual cost-stream controls | 20/20 passed | Includes the real native stream; no skip |
| Two full affected native integration suites | 23 passed; 4 top-level helper entries ignored and parent-invoked | Scope described above |
| Source-integrity controls | 43/43 passed; exit zero | Expected negative-case `FAIL` receipts remain in the raw successful suite log |
| CI contract controls | 177/177 passed; exit zero | Contract/mechanism checks, not all workflow jobs executed |
| Repository checks | PASS; 6,554 local links | Does not establish remote URL availability or production readiness |
| Distributed source inventory | PASS; 1,573 embedded inputs | Inventory consistency, not coverage of every runtime obligation |
| Native workspace formatting | `cargo fmt --all ... -- --check`, exit zero | Fixed native workspace |
| First strict workspace/all-target/all-feature Clippy | **FAILED, exit 101** | Offline cache lacked `foreign-types 0.3.2` archive |
| First locked/offline all-feature workspace graph | **FAILED, exit 101** | Same missing locked archive |
| First locked/offline fuzz graph | **FAILED, exit 101** | Local index lacked `libfuzzer-sys` |
| Restored locked/offline all-feature workspace graph | **PASS; exit 0** | Cargo metadata resolution only; 182 resolved packages and 26 workspace members |
| Restored locked/offline fuzz graph | **PASS; exit 0** | Cargo metadata resolution only; 150 resolved packages and 1 workspace member; no fuzz campaign executed |
| Restored strict workspace/all-target/all-feature Clippy | **PASS; exit 0** | Native workspace static checks with `-D warnings`; not complete runtime-test execution |

The subsequent local cache review identified eight missing locked crate archives: `foreign-types 0.3.2`, `foreign-types-shared 0.1.1`, `openssl 0.10.81`, `openssl-macros 0.1.1`, `openssl-sys 0.9.117`, `arbitrary 1.4.2`, `jobserver 0.1.35` and `libfuzzer-sys 0.4.10`. Five index records were present; the latter three were missing as well. Cache recovery itself does not establish a quality pass. The subsequent commands below provide separate successful observations using `--offline --locked`; every before/after receipt verifies source `39336622c63df1ae746d83a76bb53202cd01ba17`, tree `42fbd7d5a7f00b75000cb4aa242e578a8f941d59` and the same 27,663 tracked entries / 2,527,920,394 bytes. No lockfile change or relaxed dependency resolution was used. The first three exit-101 failures remain in the packet.

### Restored quality receipts

All three command receipts and their raw logs are under `validation-39336622`. The elapsed column reports each command receipt's recorded duration; Clippy's own terminal line records completion in 4m 45s. Each original log's bytes were checked against its receipt's SHA-256. Graph results were parsed from the retained Cargo metadata JSON, not inferred from cache availability.

| Receipt | UTC start | Receipt elapsed (s) | Receipt SHA-256 |
| --- | --- | ---: | --- |
| `workspace-graph-restored.json` | `2026-11-10T09:23:45.101306+00:00` | 31.760472322 | `37251e4982300ff560ec78303b2c87fd0b9f44825303ba9b5a8fa61b48800256` |
| `fuzz-graph-restored.json` | `2026-11-10T09:24:16.928261+00:00` | 12.612425099 | `735ce1d5be209e07ef048d9dc1cb98d641947b6fcca0abcf4c176cbc00df6be2` |
| `strict-workspace-clippy-restored.json` | `2026-11-10T09:24:29.649681+00:00` | 315.680053847 | `3b0696e64744ce72ad84dca7766a503faf582ba5234e23320c567f29c0cd91c8` |

The corresponding raw-log SHA-256 values are:

- `workspace-graph-restored.log`: `cd46ee911b007f1318236d67d11803ef662954741cd899b04919dacf54459330`.
- `fuzz-graph-restored.log`: `e1d597f9dfa9fe094b55b40c2c852caacea9314409b378b0dbe78f56218d0a69`.
- `strict-workspace-clippy-restored.log`: `0df2f78b3c726568b10ab961e5ad51d2edb2e63b886ba07a7368f0de511f3efd`.

The exact recorded commands, each within a 900-second process timeout, were:

```text
cargo metadata --offline --locked --all-features --manifest-path trillionnium/Cargo.toml --format-version 1
cargo metadata --offline --locked --manifest-path tests/fuzz/Cargo.toml --format-version 1
cargo clippy --offline --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features -- -D warnings
```

**The evidence-only child carries these local observations without changing their executed-source identity. Hosted execution retains its own source and result.**

The preliminary development cost run is retained separately under `precommit-from-zero-filter` in the raw archive. Its CPU measurements and scoped precommit Clippy observation are not substituted for the final execution cohort or for the complete-workspace quality gates.

## Evidence inventory and claim boundary

The [raw archive](raw-records.tar.xz) contains 48 original files, 27,224,833 uncompressed member bytes. Its [member manifest](raw-records-manifest.json) supplies every path, size and SHA-256. The [machine-readable summary](summary.json) preserves command outcomes, cost denominators and qualification limits.

Archive bytes: **1,221,392**. Archive SHA-256:

```text
0dd1ed9f2b47858b744d19d48138b1dfb62f40d63eb53940b2834aaa430fa4b6
```

| Archive group | Retained contents |
| --- | --- |
| `validation-39336622` | All twelve original command receipts with their exact logs, including the three initial failures and three restored passes |
| `from-zero-filter-exact-head` | Native JSONL, execution/source/binary identities, build/preflight/Rust logs, actual-stream controls and parent runner stdout/stderr |
| `precommit-from-zero-filter` | Earlier development experiment and scoped preparation checks, kept separate from fixed-source qualification |
| `pre-fix-fifo` | Both original failing native subprocess observations and the selected-source identity receipt |
| `dependency-material` | Exact-lock cache recovery/import receipt, local cache review and missing-material list; no lockfile changes |

The archive includes only regular files with relative paths. Its manifest binds delivery bytes; it does not authenticate the physical machine or supply a stronger execution claim. Reproducing the source commands requires the measured source checkout and its locked dependencies; checking raw records alone is a consistency operation.

The following remain open:

- Independent authorized/funded task demand, data rights and real resource/payment attribution.
- Correct complete computation, independent delivery, custody/readback and ordinary consumer use.
- Independent frozen future-task model net benefit including all failures, training and lifecycle costs.
- The minimum cost over every legal strategy, setup/cache/task/nonce/multi-target amortization, GPU/ASIC and complete classical/quantum resource laws.
- Public service liveness under the original acceptance budgets and cross-connection, cross-identity, restart and independent-receiver responsibility. Lifetime PQ authentication budget exhaustion/recovery remains open; resetting responsibility is not a valid repair.
- Joint DAA/timestamp/chainwork security, variable participation, congestion/hidden ancestry, public prefix/chain growth/chain quality and confirmation risk.
- Evaluator common control/collusion, holdout contamination, copied models and fabricated demand.
- External effects under real reorganization/partition/ACK-loss/recovery with target idempotency, durable reconciliation and unresolved Unknown states.
- Same-inode/same-length live native journal mutation beyond the existing device/inode/length guard; this needs a separate design and cost review, not an unmeasured full-prefix rescan.
- Whole-chain post-quantum security, fixed-SHA/QROM obligations and complete quantum-mining qualification. Local OpenSSL 3.5.7 and static all-feature Clippy do not supply runtime PQ qualification.

All qualification and production-activation flags remain false; production refusal remains in force. This packet neither merges the candidate, changes default service policy, grants payment/adoption/consensus credit, nor activates production.
