# Current PQ authority, recovery and response completion

User date: 2026-11-04, America/New_York. Original command timestamps use UTC.

**Component fixes and exact-source checks; all six whole-chain qualification
domains remain HOLD / NO-GO.** This record continues the existing integration
[PR #688](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/688),
[sole plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md),
and [recovery/release boundary contract](../../docs/security/PQ_RECOVERY_RELEASE_TRANSPORT_BOUNDARIES_V1.md).
No activation, protected-main merge, approval, production key or deployed service
change is part of this work.

## Fixed source and integration

The source used for the native test executions is commit
`e05b44ccd9782d0a3367ea4ca9913c0310d4a3f0`, tree
`da83f586e9f896544cf1e3cff9bfb76bcc8f682d`.
Each completed e05 command recorder verified all 9,589 tracked entries /
954,771,487 bytes before and after its command. This is a head checkout;
the prospective merge with protected main was not executed.

The code extends `47b4a62463d8e1371a175c74196d52d99c5fccb8`.
Eight recovery/release/Cell files are exact, narrowly selected blobs from
`b525fbc6dc780343c78710c98a94616f7cff59e4`; the older branch was not
copied wholesale. Existing Cell deadline changes remain intact.

Concurrent head `ef1fa4d48ab9894f3d7a4b1c797ca9e7e490b155` adds or
updates 82 evidence paths. The initial intermediate tree
`f2cd33c206974a807b25789aab7ef33a552afe8d` preserves e05 inputs outside
evidence. That statement applies only to this intermediate.

The next head, `04be5f02c84cf5cb626a53f34bc03a5bd6ff5137`, also changes
Growth activation and monetary/capacity scans. Joint code commit
`78874ae144fe7ca1adc6805a646fdc433d33028e`, tree
`138f154b90666416ae4968009655b733209b9061`, has ordered parents
04be and e05. Its eight non-evidence differences from e05 are explicitly listed
in [source-delta.json](source-delta.json). The six incoming source/test files
and fifteen e05 source/document files retain their exact blobs. Both sides'
generated inventory and corpus changes are combined; JSON key ordering is
serialized deterministically.

The publishing merge also preserves the later
`2e7fbaeabc396d501d9d802adc63df963f1d288c` plan/evidence additions.
The joint checks below belong to 78874ae; the native tests belong to e05.
Neither source identity is relabelled as an execution on the publishing commit.

## Behavior changed

1. **Checkpoint recovery and live use:** structural-only open cannot read,
   advance, serve or export a trusted runtime checkpoint. Live operations recheck
   the complete durable journal against the retained count/root and exact head.
   Same-inode truncation, equal-length prefix edits and old-head replacement
   cannot reuse cached authority. Positional fixed-record reads preserve the
   append cursor; head reads are bounded to the exact encoding plus one byte.
   Verification is O(journal records), with fixed record-buffer space.
2. **Publisher versus activation authority:** a current activation signature
   cannot extend an expired manifest or carry its publisher authority across
   root rotation. The current publisher must authorize the same content at a
   higher manifest version. Replay rebuilds generation and expiry from signed
   events. Previously accepted histories violating these rules may now be
   refused; automatic legacy-history reconciliation is not implemented.
3. **Cell observations:** use requires the supplied current network, parameter,
   key pin, generation, sequence and time, including key retirement and the
   original signed lifetime. The time-only API is removed. The CLI supplies its
   per-command acquisition policy. A copied old view still does not establish
   current-owner freshness or atomicity with a real effect.
4. **PNQ2 response completion:** after canonical decoding, payload commitment
   and real ML-DSA verification, the client rechecks the original absolute
   deadline and original signed expiry. Refusal does not refund a consumed
   sequence, undo a remote effect or authorize a new retry. The three regression
   tests use real RustCrypto ML-DSA signatures and TCP framing; the controlled
   peer is not a durable Node execution owner.
5. **Quantum-model report identity:** writer and reader use original Git
   objects with replacement processing disabled. The reader validates a real
   commit, exact enumerated model-source hashes and the claimed per-file
   committed/uncommitted state. A recomputed report hash alone cannot validate a
   fake commit or a replaced commit/tree. Historical execution, unrelated tree
   dirtiness, mining costs and cryptographic soundness are outside this proof.

## Actual validation on the fixed commit

The [reproduction record](reproduction.json) contains this round's final command
argv, statuses, source identities, test summaries, archive members and SHA-256.
Historical command details remain in their original archived receipts. The compressed
[original command records](verification-records.tar.gz) preserve raw receipts
and logs, including failed and cancelled observations.

| Scope | Actual result |
| --- | --- |
| M09/M15 | 354 executed tests plus 9 compile-fail documentation tests pass: 307 M09 library, 29 CLI, 18 M15 library, 9 documentation |
| M03 selected targets | 15 cold-recovery + 15 binary-module + 3 CLI-refusal tests pass |
| Source, claim and CI controls | 213 pass: 43 + 35 + 4 + 22 + 11 + 98 |
| Conditional DAA model/report tests | 19 pass; this is arithmetic/report validation |
| Strict Clippy | Four specified packages, all targets and features, warnings denied: pass |
| Workspace format / locked Cargo graph | Pass; 26 workspace members, 175 default resolved packages, 180 lockfile entries including optional dependencies |
| Canonical Node regression attempt | Cargo exit 101; rustc terminated by SIGKILL before any selected test executed; cause not attributed |
| Diagnostic Node regression attempt | 3 pass / 0 fail / 0 ignored, 1,062 filtered out; only Node debug information is disabled, and this cannot replace the canonical gate |

The three new Node test names are:

- `pq_client_completion_keeps_real_signature_and_response_context_checks`
- `pq_client_late_verified_response_cannot_renew_original_deadline`
- `pq_client_verified_response_rechecks_original_signed_expiry`

The source corpus checks 473 exact blobs / 391 required paths. The required
meaningful-test roster contains 52 unique controls. These are inventory counts;
they do not assert that 52 native controls or the full workspace executed here.
The earlier 363-component pass is retained under its own base-plus-five-blobs
identity and is not added to the new committed-source pass count.

### Joint-source validation on 78874ae

The seven joint-source command records verify 9,671 tracked entries /
957,029,729 bytes both before and after execution. All seven commands succeed:

- Strict Clippy for Node, mvcc-fee, checkpoint-store, release-bundle and
  data-availability, with all targets/features and warnings denied.
- 97 controls: 43 source-integrity, 35 PQ source and 19 conditional DAA/model
  report tests. These repeat specified controls on the joint source; they are
  not added to e05's totals as distinct coverage.
- Full workspace formatting, locked offline Cargo graph, generated source
  inventory, exact PQ corpus and repository/Markdown checks.

Native Rust tests were not executed again on 78874ae. In particular, the new
Growth/monetary composition and the original business acceptance criteria cannot
inherit the e05 native results. The canonical Node build failure and the
separate diagnostic profile retain their original status and source.

### Failed and incomplete observations remain visible

The old checkpoint implementation fails four new cold-recovery controls
(11 pass / 4 fail). The post-fix all-target attempt fails one of its first
library tests because AF_UNIX bind returns EPERM (10 pass / 1 fail). Three
positive cross-process socket tests are not included in the later CLI selector.
Neither observation becomes a full checkpoint-daemon pass.

The original M15 red run is 1 pass / 2 fail; M09 is 3 pass / 2 fail.
The M09 red fixture maps the new current-view test to the old time-only API so
the observed failure demonstrates wrongly accepted authority, not just an API
compile error.

A fresh isolated replay of the saved intermediate pre-replacement implementation
produces one unittest with three failed subcases: wrong writer commitment and
two missed reader rejections. Its implementation has no claimed commit identity.
It is labelled as a new replay, not a reconstruction of an earlier lost log.
All replacement refs belong to isolated temporary repositories.

A duplicate 43+4 source-control invocation was cancelled with outer exit 130.
Its raw receipt remains running/incomplete and is excluded from all pass totals,
even though the child log contains test output.

## Reproduction

Create a clean checkout of the fixed code commit on an allowed fix/chain-* branch.
Run `bash scripts/project-preflight.sh` before builds. Use Rust 1.95.0,
the unchanged Cargo.lock, one Cargo job, no incremental compilation and one Rust
test thread. Exact commands and environment observations are in reproduction.json
and the original receipts. The full-feature Clippy command used the existing
isolated OpenSSL 3.5.9 provider, including its recorded binary SHA-256; provider
preparation is defined by
[prepare_pq_provider.sh](../../scripts/ci/prepare_pq_provider.sh).
Do not substitute system OpenSSL for a pinned native-provider test.

The canonical command which did not complete is:

```sh
cargo +1.95.0 test --locked --offline \
  --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --lib -- pq_client_
```

The separately recorded diagnostic adds only:

```text
--config profile.test.package.trnm-pon-node.debug=0
```

That diagnostic can establish a functional response-boundary observation when it
actually runs. It cannot establish canonical build acceptance, target-hardware
timings, the original hostile-W1 business criterion or a release qualification.
The archive contains no production secrets or generated signing identities.

## Six domains: remaining closure evidence

| Domain | Still required |
| --- | --- |
| Every authorization/effect entry | Real account, governance, installer, recovery, CURRENT, FinalUse and provider adapters under the current root at the atomic consuming owner; stale-view races, retirement, unknown effects and stable-ID recovery. The trnm-release-bundle::pq_release authority kernel still has no production caller in the inspected Chain tree. |
| Work/proof security | Full native W1 relation and witness obligations, explicit quantum security games, compiler/backend binding, composition and rejection economics; any added proof backend must meet its own soundness and cost goals. |
| Quantum mining and fork choice | Cheapest legal classical/quantum producer including preprocessing and amortization; resource/hardware assumptions, DAA/timestamps, cumulative work, reorganization, propagation and correlated/network adversaries under one coherent model. |
| Historical migration/antirollback | Rights, nonce/debt floors and already-entered external effects survive mixed historical replay, restart and restored snapshots; independent fresh complete checkpoints and real provider reconciliation survive distinct fault domains. |
| Capacity/malicious input | Actual PQ wire size, network/verification/queue/RSS/tail costs and recovery work at the complete service. Original four seconds, at least sixteen hostile W1 workers, depth-six/required-work confirmation, CPU/Host limits and 4,105-block History are unchanged. |
| Independent end-to-end acceptance | Frozen complete Chain/runtime source pair, reproducible deployment, independent review/operators/fault domains, real failure experiments and governed activation. The existing three-independent-administrator/72-hour obligations require actual evidence. |

Internal parallel review, component signatures and local test passes do not
provide independent organizational acceptance. All acceptance and activation flags
remain false. [Issue #629](https://github.com/TrillionniumFoundation/Trillionnium-Chain/issues/629)
and [issue #639](https://github.com/TrillionniumFoundation/Trillionnium-Chain/issues/639)
retain their existing whole-chain and original-liveness gates.
