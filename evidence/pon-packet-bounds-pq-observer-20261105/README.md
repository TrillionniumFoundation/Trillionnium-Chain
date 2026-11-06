# Stored packet copy bounds and settings-selected task observations

## Two concrete repairs

Three retained-packet reads previously copied an arbitrarily large local BLOB into Rust before comparing or decoding it: `Node::packet`, admission's existing-ID check, and `exact_packet_observation`. They now share an actual SQL projection retaining at most **1,048,577 bytes**, one beyond every legacy and settings-selected PQ Packet codec's unchanged 1 MiB ceiling. Empty BLOBs, SQL NULL, other SQL types, query ordering and original error/provenance checks remain intact. Oversized-row rejection is still performed by the existing comparisons or codecs. A resource regression executes the production projection itself, so deleting its clamp fails even if error messages remain equal.

A separate genuine bug surfaced in the new cold-reopen regression: `unique_acceptance` decoded every transaction as legacy, so a valid NPQ6 transfer caused `TRANSACTION_CODEC` after its block became active. The observation now chooses its decoder from protected account settings, keeps the native account identity and exact signed-wire ID, and supports real kind-5 task settlement across all five PQ profiles. Transfers return no accepted-task binding only after successful selected-profile decoding. No blanket PQ bypass, legacy fallback, new wire domain or authority is introduced. Root, generation, current settlement, ambiguity and original error-order checks remain.

## Exact source and retained failures

Published base: `ae781122c3d3dc2ec81031f929f62d918502cd6a`. Final local validated source: `0832d38067cd901a0ec6063558963b549243819c`, tree `99cb57f83dfe2f822d3a678e018e0afc4a28c706`. The archive contains the exact patch from that base. Delivery adds only this evidence.

The first local source `3ed32522db87ef55f8d9cd2dd9c4c6bb6f598803`, tree `10fd165334bac6091b557db7f3a82ef1fabbfaa4`, compiled and ran **5 passed / 2 failed**. Its source patch, full failure log and file hashes are retained. The legacy failure compared an inactive pre-close block with cold-open recovery's activated block; both fixtures now explicitly activate before comparing complete observations. The PQ failure exposed the real observer decoder defect described above. The original PQ success assertion, signed transfer, cold reopening and independent original-query readback remain; neither failure was converted into expected success or hidden by skipping coverage.

## Final validation

Original Rust 1.95.0 test profiles, locked dependencies and default runtime features produce **126 distinct passing native tests**, zero failures:

- Native authenticated owners: 95 passed, one pre-existing ignored observation retained. The seven packet regression tests are a subset.
- Settings-selected task observations: three tests, covering all five PQ profiles, real signed M06 reserve/receipt/accept settlement, exact identity fields, malformed/profile/context/state refusals and legacy ordering.
- Admission wire: two passed. Public request observations: 22 passed.
- Original accepted-task integration: four passed across legacy-v2 and authenticated-v1, including CLI readback, cold restart, reorg, receipt-only/ambiguous packets and altered current task state.

Strict workspace/all-target/all-feature Clippy, formatting, 37 source controls, 100 CI controls, 524 registered source pins, 23 inline pins and unchanged generated inventory pass. Repository validation also passes with 3,332 local links; its dirty-candidate label records the newly added evidence files, not changed Rust validation inputs. The existing release CI lane keeps all original checks and additionally requires the new packet and observation controls plus original accepted-task integration cases by exact name. Separate read-only code reviews found no blocking issue; these are not external security acceptance.

## Scope and remaining limits

The allocation defect requires damaged/restored local storage; remote clients cannot insert valid oversized packets. This change bounds Rust-owned copies at these three reads, **not SQLite materialization, page traffic, process RSS or all repository reads**. Operator-owner prechecks still have separate packet reads in `operator_mining_owner.rs` and `operator_continuous_owner.rs`; no whole-admission bound is claimed. GrowthPacket uses a separate codec.

Default-feature tests and all-feature linting do not qualify the pinned OpenSSL 3.5.9 runtime provider (local installation is 3.5.7), PQ-128, production activation or the original four-second/at-least-16-hostile-W1 business gate. No such limit or acceptance criterion changes.

Reproduce the lib selectors with `cargo +1.95.0 test --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --lib <selector> -- --nocapture --test-threads=1`: `native_fixed_blob_tests`, `store::task_observation::tests`, `store::native_authenticated::`, `store::admission_wire_tests`, and `ingress::public_v3::request_observation::tests`. Run the integration with the same command replacing `--lib <selector>` by `--test accepted_task_observation`.

[Exact identities and hashes](verification.json); [complete logs and source patches](raw-validation.zip).
