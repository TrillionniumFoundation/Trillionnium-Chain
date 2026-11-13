# Cell branch consolidation review

Status: **HOLD for final composed-source qualification**. This review covers
the 46 Cell-related independent tips in [the exact ledger](cell-tip-ledger.json),
starting at `b683714cdd5ba241c16c335a81aebc12c1581902`. The reviewed code checkpoint is
`eedc32adadde4992787073f93340ea4cc531cbe7` (tree `ea9504a313f547d3322298c05e78345c606b27a2`).
It records source selection and bounded local validation. Other lanes retain
responsibility for the non-Cell portions of mixed branches. Network activation,
FinalUse, independent custody and whole-chain post-quantum qualification remain
outside these observations.

## Selected changes and boundaries

The selected tree includes bounded iterative BEP5 lookup, original-budget
controlled restoration, explicit RS(6,4) failure-domain controls, readiness
initialization handoff, historical retirement readback after extent reuse,
endpoint-keyed soft peer-failure ordering within one existing release budget,
independently pinned local assembly/XOR research, and a separate read-only TPQ1
C conformance oracle. Current complete-release, native shard, retained pin-set,
sealed-loader and cancellation owners remain selected.

The #818 parallel PQ discovery-v3 implementation is preserved in its original
history and evidence, with compatible generic source-detection controls
retained. The sole plan already selected #823's authenticated epoch-v3 owner.
Both histories use CDP3/CDQ3/CDS3 and the same database identity/version, but
their signed domains, wire layouts and authority schemas differ. Current tests
explicitly reject reinterpretation of the parallel profile. Old PCP2 raw-key
profiles likewise remain historical; fresh verification and original lease
bounds map to the selected paired wall/monotonic receipt. No alternate protocol
fallback is registered.

The old segmented `runtime_root` and ordinary action-catalog/configuration
producer remain archived alternative owners. This does not assert that current
complete-release owners implement that older segmented-runtime feature. Future
adoption requires a distinct design integrated with the selected runtime and
retirement owner. The ledger records this limitation instead of inventing
equivalent coverage.

The Cell half of e6c622a16c is ported. Its Node half still requires same-budget,
same-journal completed-successor validation before retirement; an already
retired readback cannot adopt a newly offered successor. The Node lane owns
that composition and its controls.

## Review method and preservation

The ledger records every full branch head, merge base, and original core-path
set through the [assigned snapshot](assigned-tip-snapshot.json), along with
source outcome and exact historical/starting/selected Git blobs. It covers
113 distinct source variants, including four additional old runtime
producer files and three TPQ1 C-oracle files. Repeated six-file Cell deltas in
older stacked branches share one semantic review and retain an explicit mapping
for each tip. A textual clean merge is not semantic acceptance.

Nine original branch heads are already ancestors of this Cell checkpoint.
Remaining original heads must be preserved by the root integration DAG or
durable refs before branch retirement; a compatible port does not replace
original provenance. Original evidence trees are compared by Git mode, type
and blob identity in `original_evidence_checks`. Existing failed, held, empty
or stale observations remain historical facts.

The initial local composition temporarily included the parallel pq3 owner; it
was removed after namespace review in `70a4c6b1fb`. An intermediate historical
plan conflict and obsolete one-branch workflow were corrected in `822b57df8c`.
These intermediate commits remain visible. Rust 1.95 strict checks later found
three research lints and export formatting, fixed in `91c65e770f`, then a
redundant unit expression in the adopted discovery example, corrected and
formatted in `6c4873325e` and `eedc32adad`. Original failed command receipts
remain beside later reruns.

## Validation scope

Exact command receipts and complete logs are listed in the
[validation index](validation-index.json).
Each records its commit/tree, arguments, environment, tracked-byte identity
before and after execution, exit status and log digest. The first 87-test run
predates removal of parallel pq3 and is historical. The 46 focused controls at
df2cfb403d passed. Finalized checks target the separate checkpoint above and
cross-check the selected set against its native test catalog. The TPQ1 C run
at d087b37c1d passed ten tests; the versioned nested-PQ source control also
passed there. No earlier receipt is rebound to a later combined candidate.

Final repository qualification still requires shared corpus/register/source-pin
reconciliation and exact-source gates after all lanes merge. This record keeps
that HOLD; source coverage and historical passing runs do not establish final
acceptance. The per-command validation index records actual statuses, including
failed attempts and any rerun, rather than treating this prose as a test result.

## Per-tip ledger

Group names resolve to detailed reasons, current paths, applied commits and
remaining owner boundaries in `cell-tip-ledger.json`.

| Exact tip | Branch | Cell review group | Original head retained here |
| --- | --- | --- | --- |
| `21c218cf552c6a10d1abca5d79844a02baab7123` | `fix/chain-cell-storage-validation-349a` | `bounded_lookup_restore` | Yes |
| `a67d83a05d6ff4c2fdc4a5fd5c23fc38d38b563d` | `fix/chain-cell-native-shard-674c72-20261110` | `native_shard` | Yes |
| `a7f08aab5183e914230b56324760cb43609e436d` | `research/cell-three-domain-rs46-evidence-20261110` | `rs46_domains` | Yes |
| `43e10d4dded2404f2b6ae8851a68173d9d792be6` | `fix/chain-cell-storage-network-v3-20261108` | `parallel_pq3` | Yes |
| `a9c2ef6971eb3783d4259d6594c2904ea274501f` | `fix/chain-seven-gates-followup-20261108-3a20` | `seven_gates_current` | Root retains |
| `1e1cc50a0367fd29f48d00db20f35134900c656e` | `fix/chain-pq-cell-readiness-rustfmt-source-pin-20261107` | `readiness_current` | Yes |
| `e6c622a16c6770073435f49cf02a6808b56312b0` | `fix/chain-crossrepo-evidence-e0c10` | `retirement_readback` | Root retains |
| `d2c503987c8c7f604714a8842c257793306ecb16` | `fix/chain-throughput-six-axis-20261106-bf693` | `pq_pins_dependencies` | Root retains |
| `4be50aa40ed537b8a06475984a8da4141e44cf77` | `fix/chain-cross-repo-gates-20261106-5edd` | `pq_pins_dependencies` | Root retains |
| `86054a6b6d329ac7c6d89d708bb036e1a98e2d77` | `fix/chain-evaluation-phase-observer-20261104` | `network_session` | Root retains |
| `c09e681b043cad8141a659ca40a9b19a2eca9d5e` | `fix/chain-recent-store-pin-20261104-gpt6` | `network_session` | Root retains |
| `e62eb3a4f35cf9fc5bf7f3092f86d441d0c4cd29` | `fix/chain-cell-rendezvous-readiness-20261103-gpt6` | `rendezvous_ready` | Yes |
| `9bd3d43edf6e0f22183d71f52210ec4e0b32dd2e` | `fix/chain-hex-decode-20261104` | `network_session` | Root retains |
| `c8c095bb2eee9272dcc77421f055897e6806da12` | `diagnostic/chain-da-sequence-1bac-20261104-gpt6` | `diagnostic_readiness` | Root retains |
| `433948bd39792ba578f9de3c3d4793ac58411780` | `fix/chain-rejection-cost-v2-20261104` | `network_session` | Root retains |
| `a43951695bb808b3952d1e9ee99d8f9b603a4fc1` | `fix/chain-w1-native-control-inputs-20261103-gpt6` | `rendezvous_ready` | Root retains |
| `002cd506c81e1dfac4a656bfcd03b5b233dbc923` | `fix/chain-native-convergence-20261029` | `native_convergence` | Root retains |
| `8db16f8f5d03ca8c192556a815fd2a74704edd3c` | `fix/chain-pq-rust-gates-exec-request-clock-20261031` | `pq_clock_controls` | Root retains |
| `21cac401bcb53fcb375717166800c011bfb14d12` | `fix/chain-w1-receiver-layout-bound-20261031` | `network_session` | Root retains |
| `9baae3670011cc719249ed46fe33b0b50e75a31a` | `fix/pq-relay-replay-before-payload-digest-20261030` | `network_session` | Root retains |
| `95939e1380f21dcf3209acaee70e29fcf0141d6c` | `fix/pq-hepta-context-postverify-20261030` | `network_session` | Root retains |
| `9fcd3fefdc2f4fd277fa8d9176846b34c6d0c342` | `audit/pq-claim-json-exponent-boundary-20261030` | `network_session` | Root retains |
| `722eadfaaa4f489fd0058e3dbc7f1e3cf72465c1` | `fix/pq-recovery-postverify-trusted-clock-20261030` | `network_session` | Root retains |
| `a4ec19ec8c167bad2499ab2eee724405dd318832` | `audit/cell-swarm-605-on-p0-ci-610-rustfmt-20261030` | `swarm_local_research` | Root retains |
| `5dc4c933d298e955a16eb4a1b7ab9688a7a6862c` | `audit/cell-swarm-owner-pinned-xor-repair-20261030` | `swarm_local_research` | Yes |
| `8141887759527ccb9d033a88aa89fa59310101ec` | `fix/pq-pcp2-postverify-lease-freshness-20261030` | `legacy_pcp2` | Root retains |
| `225b70cd94f5720fa046a0e8446cf9448466e70e` | `test/pq-claim-isolation-with-duplicates-582-20261030` | `network_session` | Root retains |
| `aa527e571fc9e24bb08cb92a058bad07bf708108` | `fix/pcp2-consolidated-expiry-581-20261030` | `legacy_pcp2` | Root retains |
| `ec8b909352582158ba52018ac2202a85e92790a6` | `test/pq-claim-cli-isolation-578-20261030` | `network_session` | Root retains |
| `28192fc4c9c78bf93d05d1aa3bbd2488ec5a1b1a` | `fix/pcp2-combined-fetch-server-expiry-20261030` | `legacy_pcp2` | Root retains |
| `e9f9228ed92c01977e4c94d1d142d3606701c14c` | `fix/pcp2-server-expiry-latch-574-20261030` | `legacy_pcp2` | Root retains |
| `fdc2c3643d214ac17ed6415d0a185336e4142407` | `fix/pcp2-fetch-expiry-anchor-571-20261030` | `legacy_pcp2` | Root retains |
| `b23e465cae259948201f7a216c2c23cf7332cdb8` | `fix/pq-cell-provider-reply-pcp2-20261030` | `legacy_pcp2` | Root retains |
| `e71c4131842d6af16929cab40d1c9938a00163c1` | `fix/pq-m09-offpolicy-preflight-20261030` | `legacy_pcp2` | Root retains |
| `5beee6b17be2ead2a3862ec2a870b5c55f810806` | `fix/pq-claim-exact-bools-560-20261030` | `network_session` | Root retains |
| `a6e231cce07aec408e957b0875b094bfd1d21b84` | `fix/pq-cell-provider-pinned-v2-20261030` | `legacy_pcp2` | Root retains |
| `ead1000360d24247f3c6159d50b2c8663ff4af4f` | `fix/chain-pon-verification-cost-20261028` | `sequence_fixture_current` | Root retains |
| `b68c9523a1abc699883154849d657db764feffbe` | `docs/chain-audit-remediation-20261022` | `alternate_runtime_owner` | Root retains |
| `b2a57e0f98fad412b71c982c10d94795ca7850a4` | `fix/chain-cleanup-snapshot-stop-order-20261029` | `sequence_fixture_current` | Root retains |
| `d08ff108d90324f103a0eff39b213a156d4d0cfc` | `research/chain-w1-receipt-loopback-20261029` | `sequence_fixture_current` | Root retains |
| `007b80cc99ba52fe7afcd6d0e0dea52628f5a026` | `research/chain-w1-full-cost-profile-20261029` | `sequence_fixture_current` | Root retains |
| `31a8f1775f6940c303004fd97407ef13dc14d29b` | `research/chain-w1-preflight-boundaries-20261029` | `sequence_fixture_current` | Root retains |
| `e67d26f5ab91f526206fe11ae56a46e210ed6c34` | `research/pq-pql9-native-tpq1-crypto-20261027` | `tpq1_c_oracle` | Yes |
| `c014bbbd604dad68f0a5d87a8f35a5d4fe5ce181` | `research/pq-cell-temp-schema-ack-fence-20261027` | `custody_schema_ack` | Yes |
| `871ade83cd0bf43adbbefc397a88b187bf7bbd5d` | `fix/chain-ci-hardening-20261015` | `regular_store_current` | Root retains |
| `5862e4427e918f10f50c10844e411f0ed3f70d66` | `dependabot/cargo/trillionnium/rusqlite-0.40.2` | `dependency_current` | Root retains |

## Final local results

At `eedc32adadde4992787073f93340ea4cc531cbe7`, package formatting and
strict all-target/all-feature Clippy passed. The native catalog lists 943
tests; all 46 selected controls executed once and passed, with 897 filtered
and zero failed or ignored. The [roster check](validation/cell-finalized-test-roster.json)
compares actual names against that same-commit catalog.
Earlier failed formatting and Clippy attempts remain in the validation index.
The later documentation/evidence commit containing this record is not relabeled
as the tested code checkpoint.
