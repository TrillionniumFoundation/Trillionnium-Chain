# Request outcomes, authenticated evaluation and bounded Cell work

This continuation belongs to existing integration PR #688. Its regression base is
`93e207c8d2ccb8509f78566223abc371b9d8118b`. It changes the actual request-report
consumer, Growth V2 evaluation business APIs, and bounded Cell data paths.
It does not promote a qualification or activation flag.

The preserved concurrent history includes Cell residency/prefetch commit
`5c070abeb61d0ea8702fa94fffe9330d1699119c`, inventory commit
`a4a0e2b561f057cfa3189979c5bf11f3a0eb2353`, model-evaluation binding commit
`d0737cf5434894ce47fad8082376fc417313c2cb`, the default-off legacy reorg
observation changes in `bd2777f9cc74df10ba07ae8202584ed0fb90a519`, recovery
pin/PQ release changes in `245146c7d2e6f7dfcda463f6a7dd342d4d7ca818`, and the
later publication lineage through `03163dcb849a15cd267fcaf704a533a88cd54131`,
including detached-admission, formal W1, quantum and CI changes, followed by
Cell storage merge `e94781d2323f5dc8987e1eb7ed2bef23ee8745c3`. Source pins
and plan entries retain those changes. The manifest records the exact final
immediate parent, tree and source fence, checked against Git and the current
dependency graph. The concurrent `245146c` and `e94781d` dependency changes
are separately recorded and checked against exact Git Cargo inputs and actual
before/after metadata. The first adds the three reviewed M15 dependency edges;
the second promotes M09's serde dependency and adds normal serde_json while
retaining its development dependency with arbitrary precision. The lockfile and
package identities remain fixed after `245146c`. Arbitrary dependency or feature
drift remains rejected. Unchanged globally resolved features do not establish
that the changed normal-library dependency closure was executed.
A narrow compatibility fix carries the original residency deadline into
`manifest_with_deadline`, preserving outer checks and publication order.

The final publication also preserves `d4816ca5d1375347d8ed341a434158e350c29bbc`,
including the later classic-evaluation binding checks and model runtime records.
Its native Cargo graph and M09 source are unchanged from the e947 composition.
No earlier native execution result is transferred to this publication.

Validation belongs to distinct source compositions:

| Source composition | Retained validation | Attribution limit |
| --- | --- | --- |
| Candidate on `93e207c` before concurrent changes | 394 native passes, 12 ignored controls | Includes 82 selected Node library passes; these results do not validate later compositions. |
| Intermediate parent `5c070ab`, source fence `b99a1e82` | 331 native passes, eight ignored controls, and eight separate Cell doc-test passes | Three full Node library-test compilation attempts ended with SIGKILL. No earlier Node passes are transferred. |
| Superseded parent `d0737cf`, source fence `95b29e02` | Its own failed Node build and any completed M06/Cell, source or Clippy checks remain separately recorded | Node compilation ended with SIGKILL before the requested Node and integration artifacts were produced. No results are transferred to the later source. |
| Superseded parent `bd2777f`, source fence `6093513b` | 324 M06/Cell passes, seven ignored controls, and three separate M06 quorum integration passes; source checks and strict Clippy passed | Node and its three integration targets were explicitly unvalidated. These 327 passes do not validate the later dependency graph. |
| Superseded parent `245146c`, source fence `f4d53057` | 327 M06/Cell/quorum passes, seven ignored controls, and 110 source-control tests passed | Full Clippy exited 101 after compiler SIGKILL during the Node library-test target. Node and its integration targets were unvalidated. None of these results validates the later publication composition. |
| Superseded parent `03163dc`, source fence `76047afc` | 327 M06/Cell/quorum passes, seven ignored controls, 110 source-check tests and 2,530 Markdown links checked | Node, its integration targets and full Clippy were unvalidated. These passes do not validate the later Cell storage changes or normal-library dependency closure. |
| Final frozen composition, preserving `e94781d` | Current static/source-pin/format/metadata checks and a separate M09 all-targets typecheck have their own receipts | All native groups, including M06/Cell/quorum, Node and its integration targets, and full Clippy remain explicitly `BLOCKED_UNVALIDATED_FINAL_COMPOSITION`. Typechecking supplies no executed-test count. No earlier native or lint passes become final-source results. |

Final M06/Cell/quorum, Node suites, source checks and Clippy each require
their own receipts, including explicit unvalidated receipts where no execution
occurred. The final manifest requires all of them, the current
dependency graph, and matching before/after hashes and path sets for the
complete native source fence.
The M09 `cargo check --all-features --all-targets` receipt is a separate merge
compatibility gate. It records its actual outcome and does not turn any
unvalidated native or Clippy suite into a pass.
An explicit blocked result remains a validation HOLD. A missing receipt cannot
be replaced with an earlier composition's result. The three intermediate `5c`
SIGKILL observations, the later `d073` SIGKILL and the `245146c` Clippy SIGKILL
remain associated with their actual source compositions. These five compiler
failures are preserved; the final unvalidated native/Clippy status does not invent
another build attempt, exit code or failure log.

## Changes and scope

The public campaign reader derives version 3 observations. It preserves the
original inclusive consumed-cost summaries while separating completed request
intervals from unfinished elapsed work. Accepted, rejected, explicitly cancelled
and unknown outcomes retain their denominators. A retained cohort's terminal
p99 is unknown if an entered request lacks its outcome or terminal duration.
Known completed subcohorts have explicitly scoped empirical nearest-rank tails;
whole-population request p99 is not inferred. Cumulative queue time is a cost
sum, never a request percentile. Duplicate JSON object keys, including escaped
aliases, cannot overwrite a recorded error or unknown duration. Historical
version 1 and 2 derivations keep their exact original output shapes.

Both evaluation observation APIs now use the authenticated Growth V2 working
partition and the complete PNP2 block identity in a single SQLite read snapshot.
They check actual candidate transaction membership, current and historical
working roots, clock bounds, depth, required work, current generation, pending
reorganization and the cold-audited storage epoch. The epoch and generation are
checked again after releasing the snapshot. Observations remain read-only and
supply no execution, adoption, reward or finality authority. Legacy observers
retain their original complete-state and ancestry-index routes. Full validation
of the bounded working partition and bounded ancestry remains; universal
complexity proportional only to touched keys is not asserted.

The explicit `growth-evaluation-observe` and `growth-evaluation-round-observe`
CLI commands retain the fixed evaluation/continuity development profile and
existing namespace requirements. Candidate, bound and clock validation precede
the source-store probe. Both require an existing database and use the private
snapshot observer; they neither initialize nor recover the source. Each CLI
invocation includes private copying and cold audit outside the bounded hot
observation. This continuation does not separately measure those costs.
The process-test fixtures admit a signed ordinary tag-6
candidate, advance the active generation, and compare exact source bytes and
filenames before and after each query.

Cell cache reads, manifest handling, chunk hashes and output materialization
check the original invocation deadline at cooperative boundaries. The bounded
original bounded serving owner checks actual response-budget exhaustion at its
cooperative intake boundary. Shared serving paths check before cache or
availability work, including persistent V2; that profile retains its own finite
admission bounds. Local chunk-verification expiry does not quarantine a peer;
quarantine still requires an actual chunk-length or digest failure. A new
actual-TCP regression records that distinction but has not been executed on this
final composition. Previously admitted work remains subject to its
original deadline and reservation. Outstanding reservations remain refundable,
partial writes remain charged, and admitted workers are joined. Expired work
does not delete already committed verified cache prefixes or published output.
The legacy serving API does not silently acquire a different policy. These
checks do not preempt an in-progress SQLite, hash or filesystem call and do not
establish cross-process CPU, memory or network isolation.

## Request-stage measurement boundaries

The existing native v4 observer supplies nineteen phase slots and four
per-request wait intervals. The v3 derivation added here consumes these actual
records; it does not synthesize a new complete request clock.

| Stage | Existing fields | Boundary that must remain explicit |
| --- | --- | --- |
| Ingress | Client construction/challenge/solution/body-response timings; server frame byte/completion records | Server recording starts after accept. There is no isolated server ingress or accept-to-close timer; client total ends at response or failure. |
| Queues | `challenge_wait`, `grant_wait`, `paid_task_queue_wait`, `cpu_wait`, three owner-wait phases | These are individual request intervals. Aggregate pending-wait counters are accumulated costs. |
| Parent state | `context`, `admission_prepare`, freshness checks in `commit` | Context is composite; parent reads and revalidation are not isolated into one pure read timer. |
| W1 | `work`, full-work outcome/CPU, optional `work_arithmetic` | A completed relation check under an arithmetic-facts profile need not mean fresh matrix recomputation. |
| Application | `execution` inside `admission` | Held execution starts after `BeforeStateClone`; earlier binding belongs to preparation. |
| Root commitment | `root_commitment` inside `execution` | This duration is already included in execution and admission. |
| Durable state | `commit`, separately `submit_result` | Commit includes freshness fences, persistence and readback. Activation and active-generation lookup occur separately. This is not an fsync-only timer. |
| Response | `response_encoding`, `response_write`, frame completion, client body-response interval | Server write completion is transport progress; the client separately authenticates the response. |
| Independent import | `history[].client_import`, native page/packet phases and Host checks | Actual ordinary verifier import and complete-page activation are observed. Nested CPU/wall spans are not additive. |
| Independent confirmation | `history[].client_confirmation`, `confirmations[].observation` | The verifier checks membership, ancestry, installed depth/work and current generation. ACK is not confirmation. |

Returned failure can follow an already durable admission or imported prefix; an
error outcome must not be relabeled as proof that no state was committed.
Calling-thread CPU excludes scoped workers, and timestamps from separate
observer clocks cannot be directly joined. There is no single measured
accept-to-independent-confirmation interval or whole-request population p99.
Bounded retention, lost records, missing clocks and the three scheduled-round
denominator remain explicit. The reader preserves those unknowns.

## Preparation, commit and authority scope

This continuation does not alter the shared executor's canonical nonce,
liability, reward, sponsor or supply transitions. Prepared results remain subject
to the existing unique writer and fresh context/parent/epoch checks. Cached key
material still requires a fresh signature check, exact key pin and original CPU
budget. Matrix/root facts do not grant live revocation, balance, FinalUse or
external-witness authority.

Growth execution still requires one M06 worker. Enabling additional workers is
not a caller-only switch: its current executor control has no child-worker CPU
accounting, and speculative account-access recording must preserve the exact
canonical witness set. This is an unresolved parallel-preparation integration
boundary, not a completed all-business parallelism claim. The native release
statement also does not supply a funded FinalUse factory.

## Reproduction

Use the repository's Rust 1.95.0 toolchain and pinned OpenSSL setup from
`scripts/ci/prepare_pq_provider.sh`. Use the final source's committed lockfile and
preserve the original workspace profiles, feature selection and provider digest.
The local execution used the
ordinary native Cargo graph with actual compiler paths for the SQLite layout
witness; no optimization, deadline, worker or memory limit was relaxed.

The commands below are reproduction targets. Listing a command does not claim
that it completed on the final composition; the source-specific receipts retain
each observed outcome.

```sh
bash scripts/project-preflight.sh
cargo metadata --offline --locked --all-features --manifest-path trillionnium/Cargo.toml --format-version=1
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
python3 scripts/ci/test_pon_public_v3_phase_read.py
cargo check --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-data-availability --all-features --all-targets
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-mvcc-fee -p trnm-data-availability --all-features --lib -- --test-threads=1
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-mvcc-fee --all-features --test evaluation_quorum_v2 -- --test-threads=1
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib store::evaluation_observation::tests:: -- --test-threads=1
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib store::evaluation_round_observation::tests:: -- --test-threads=1
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib request_observation::tests:: -- --test-threads=1
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib verifier_cache::tests:: -- --test-threads=1
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib store::detached_admission::tests:: -- --test-threads=1
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --lib store::growth::tests:: -- --test-threads=1
cargo test --offline --locked --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --all-features --test native_growth_cli --test evaluation_observation --test evaluation_round_observation -- --test-threads=1
cargo clippy --offline --locked --manifest-path trillionnium/Cargo.toml --workspace --all-targets --all-features -- -D warnings
python3 scripts/ci/check_pq_research_integration.py
python3 scripts/ci/test_pq_research_integration.py
python3 scripts/ci/test_ci_source_integrity.py
python3 scripts/refresh_distributed_source_inventory.py --check
python3 scripts/ci/check_repository.py
```

The [compact reproduction manifest](reproduction.json) records source hashes,
actual executed test selectors and counts, baseline counterexamples, compiler
and binary identities, and the retained historical-report replay. It separates
pre-composition, intermediate `5c`, superseded `d073`/`bd2777`/`245146c`/`03163dc`
and final results. Where execution is observed, final test executables
must match this composition's Cargo artifacts and recorded ELF hashes. Failed
builds retain compact diagnostics and log hashes; raw logs, raw binaries and
large evidence archives are excluded from this source delivery.
Historical report replay is not a new native campaign or a measured speedup.

## Acceptance still required

The original four-second confirmation under sixteen hostile producers and the
original 4,105-block History campaign retain their exact requirements. Complete
business confirmation, all-business touched-key scaling, target-host data-plane
isolation, external monotonic recovery, independent model evaluation and whole
PQ qualification require their own evidence. Passing the controls here neither
changes those requirements nor closes their previously failed or unknown cases.
