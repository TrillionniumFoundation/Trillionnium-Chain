# Frozen-source Node and CLI failure readback

This is a readback of existing evidence, not a new test run. Source: `e36cfb88956a0e35e53d74c5ab71c94c628439d9`, tree `b2586f06e82de55484a2e5752563e8b669c3ea17`. The original status remains **FAILED** and every qualification guard remains **HOLD**.

## Original full Node invocation

**1217 passed / 35 failed / 33 ignored**, 1285 registry entries, zero filtered; exit 101; libtest elapsed 1405.00 seconds. The original 1500-second cap was not reached. Before/after receipts bind the same verified source tree.

| Original failure group | Count | Exact observed error and stage |
| --- | ---: | --- |
| Shared recovery cases | 6 | ENOENT (2), after Harness readiness, during recovery journal initialization. |
| Journal controls | 17 | ENOENT (2) at initializer or its wrapper. |
| Release service controls | 8 | EPERM (1), `service_test_fixture.rs:70`, `UnixListener::bind(clock_path)` before clock contract. |
| Existing owner control | 1 | EPERM (1), `pq_existing_owner_tests.rs:279`, constructing the socket fault fixture. |
| Independent witness combined controls | 3 | EPERM (1), child `combined_tests.rs:330` binding `witness.sock`; parent reports early child exit at line 211. |

The 23 ENOENT cases share `Journal::initialize:390 -> Epoch::new:93 -> stamp:54 -> metadata(/proc/self/ns/time)`. The stored host observation independently records that exact path returning ENOENT. This occurs before journal file acquisition/publication. The 12 EPERM cases are actual Unix socket bind refusals; the record does not identify a specific sandbox mechanism. In particular, the eight release cases do **not** reach their separate time-namespace contract.

The final failure list and 35 FAILED rows agree. Another 22 stdout blocks contain handled or expected panic output from successful controls; they are not additional failures. Embedded child-process summaries are not added to the outer count.

## Separate CLI invocation

Registry listing succeeded and listed 4 ordinary TLS tests plus 5 witness tests. The execution command exited 101. Its targets have distinct actual outcomes:

| Target | Actual result | Scope |
| --- | --- | --- |
| `pq_tls_cli` | **4 passed / 0 failed**, 5.90 seconds | Actual bounded ordinary CLI and three refusal controls. |
| `pq_tls_witness_cli` | **0 passed / 5 failed**, 0.31 seconds | Every case fails at `support.rs:71:52`, `UnixListener::bind(w.sock)`, EPERM (1). |

The four actual passes are:

- `ordinary_binary_bad_config_pin_refuses_before_owner_creation` — Actual config byte mutation after pinning is rejected before owner creation.
- `ordinary_binary_local_certificate_constraints_refuse_before_owner_creation` — Actual local certificate constraint cases refuse before owner creation.
- `ordinary_binary_pq_tls_serve_dispatches_original_node_and_preserves_replay_after_exit` — Actual bounded loopback pq-tls-serve process: ready profile checked, Head and Submit accepted, exact request replay preserved, normal exit, durable owner reopened and downgrade attempt refused. Service is five seconds; production_activation=false and public_history_tls=false are asserted.
- `ordinary_binary_tls_nonloopback_refuses_before_config_and_owner` — Nonloopback listen refuses even with absent config; no owner is created.

The five exact witness failures are:

- `witness_existing_mode_never_creates_or_reenrolls_and_create_never_reopens` — same observed `support.rs:71:52` Unix bind EPERM.
- `witness_missing_and_backlogged_endpoints_refuse_without_owner_or_listener` — same observed `support.rs:71:52` Unix bind EPERM.
- `witness_schema_identity_and_private_key_refusals_precede_owner_and_witness_io` — same observed `support.rs:71:52` Unix bind EPERM.
- `witness_selected_binary_dispatches_replays_reopens_and_rejects_old_database` — same observed `support.rs:71:52` Unix bind EPERM.
- `witness_wrong_authenticated_service_binding_cannot_publish_ready_or_advance` — same observed `support.rs:71:52` Unix bind EPERM.

All five call `Witness::new` before starting their target CLI. Durable witness registration has returned, but listener setup fails before the intended dispatch, replay, refusal, endpoint, or binding assertions. These counts are not folded into the full Node count. Four TLS CLI passes do not qualify public transport, continuous service, or whole-chain PQ.

## Source and binary provenance

The JSON contains exact Git blob IDs, content SHA-256 values, and working-file comparisons for 13 relevant files: nine full-run fixture/implementation files plus ordinary TLS CLI, witness CLI/support, and the shared certificate fixture. All 13 have identical blobs at `1c14fab4cca9c2ad1a48c502f51eb89edeb7df50`, `b08e4f624c122175583094ea94f5c8c3150cec5d`, and the frozen source. This verifies preservation of these paths; it does not establish that unexecuted downstream assertions pass or that unrelated changes are regression-free.

The completed Node test ELF was retired after the filesystem exhausted capacity. Its retained before/after records both identify 456005312 bytes and SHA-256 `c95475ef0d50d2edd7c8fb3f89da5cc90743f673bec81671c366d373bb5ba266`; the retirement record matches both. **The raw Node ELF body is not retained.** Original full logs and execution receipts remain intact. CLI before/after binary identity records also match; this readback compares records and does not independently rehash binary bodies.

## Primary evidence hashes

| Evidence | SHA-256 |
| --- | --- |
| `node-full.log` | `1c3aa009bbea424ce9b03986de6b5f22e10234a9e3ade37d117027ab365289bb` |
| `node-full.json` | `5aedf3f6c23ee15063ea387c6bb900837293169543598d1c6b0fa16b1067b6b7` |
| `tls-cli-and-witness.log` | `be594df8a4c2b9f580f3849863d5ead6fb6816fbc785f6aa093144a5c11ec05d` |
| `tls-cli-and-witness.json` | `7a094224ec51b62a3bd0599c7060f3e5a241af47c4449c22e794b5cf1db79d3a` |
| `tls-cli-and-witness-registry.log` | `6d186aea20f8230443d2003d8973e1e627ef1f277164ff086749cb78da002403` |
| `self-time-namespace-observation.json` | `8b369cc2093cb76afd5d7fa901fb80ade1ca2691c62b48809408a03401a38a09` |
| `completed-node-elf-retirement.json` | `7bf3a62c24e4452fd6fae0e6afa67022cead7b9e8745a47074459c9a0f5a3752` |

The machine JSON hashes all 27 primary log, receipt, recorder, binary-identity, host-observation, and retirement artifacts and includes every original failure block and source line. It retains the two command receipts and both registries separately.

Next step: run the unchanged complete workflow on a supported host with exact time-namespace identity and the required Unix listener operations. Keep the original 5-second recovery readiness, 10-second recovery campaign, 30-second shared service, three-attempt cap, all other original budgets, and all refusal fences. No product test was rerun, no repository file was changed, and no service was modified while producing this readback.
