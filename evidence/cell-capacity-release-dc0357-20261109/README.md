# Complete model capacity and immutable release observations

Status: bounded implementation candidate; production qualification remains **HOLD**.
This continues [PR #836](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/836)
in [PR #848](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/848).

All final runtime observations below ran on committed source
`6ea3bf3fe13d66333bba3a8c7b97e14b4319b39f`, tree
`6c4401a94defeecb9696c2da1442dcbd27b56352` (C2). The subsequent documentation
and evidence commit does not relabel those observations as executions on its
own head. Each raw receipt retains its original source, operation and result.

## Capacity correction

The original direct BEP52 profile uses 16 KiB TCM1 chunks and at most 16,384
leaves. Combining that profile with CRP1's complete 128-record union produces
a conditional 2 MiB payload bound. This is not a general CRP1 payload bound or
its separate 2 MiB metadata limit. The retained real weight file contains
269,060,552 bytes: 65 original 4 MiB chunks, or 16,423 transport leaves,
625,096 bytes beyond the old single-descriptor 256 MiB bound.

The V2 mapping keeps the original larger storage chunks and derives their
actual 16 KiB Merkle leaves. A receiver verifies both each full storage chunk
and its subtree before publication, then the complete ordered file. CBM2/CBL2,
CRR2/CRG2 and CTS1 use independent new namespaces; old V1/CRP1 meanings remain.

The per-object structural mapping bound is 64 GiB. The complete-release owner
separately admits at most 16 GiB and 4,096 original chunk references. Neither
bound is a full-size transfer or availability benchmark. The 64 GiB structural
test repeats one actual 4 MiB chunk in a declared layout; it is not a 64 GiB
readback observation.

See the [capacity contract](../../docs/development/specs/pon/CELL_STORAGE_CAPACITY_V2.md),
[CTS1 contract](../../docs/development/specs/pon/CELL_RELEASE_SNAPSHOT_V1.md) and
[V2 research entry](../../docs/development/specs/pon/CELL_SEALED_RESEARCH_NEXT_USE_V2.md).

## Exact C2 validation

| Executed scope | Result and scope |
| --- | --- |
| Complete default-feature DA crate | **812 passed:** 762 library, 34 integration, 16 documentation; zero failed, ignored or filtered cases |
| Native Node storage-service module | **44 passed**, zero failed; 1,351 other Node tests filtered |
| V2 research example controls | **5 passed**, zero failed |
| Source-integrity negative controls | **43/43 passed** |
| Repository graph and Markdown links | **PASS:** 26 workspace packages, 27 normal dependency edges, 6,200 local links |
| Strict Clippy | **PASS:** DA and Node, all targets, explicit Node native-PQ feature, `-D warnings` |
| Formatting and complete tracked-source verification | **PASS**, exact commit/tree and clean worktree before and after |

The [DA archive](da/index.json) retains raw Cargo metadata, commands, runners,
start/end source inventories, logs, actual [test roster](da/test-roster.json)
and authoritative job terminal observations. Its exact worktree checks cover
26,680 tracked entries and 2,500,750,723 bytes. The existing independent-C
workflow's actual compile-fail case remains `VerifiedCellPqReleaseV2 (line 364)`;
its predicate and historical artifacts were not modified.

The [Node archive](node/index.json) retains the complete original-profile
storage-module run and both SQLite build outputs. The originally unqualified
Node SQLite unit actually rebuilt and emitted the qualified configuration.
The environment seed follows the repository's existing
`check_sqlite_build_requalification.py` recipe; its build fence was not changed.
Cargo used two build jobs and one test thread. No Cargo profile, assertion,
overflow-check or task-deadline override was used.

The nine added native tests cover five paged-retain cases and four recovery
cases. They include complete final readback, missing/changed last pages,
historical retired-provider capacity, four actual original recovery targets,
whole-attempt cost retention and Pending/Done reconciliation without replay.
These are bounded local fixtures, not the real 95-chunk model operation.

## Real same-operation V2 model observation

The [model archive](model/index.json) preserves the complete original inputs
manifest, independent input verification, exact executable/source observations,
native report and worker receipts. This was one fresh operation:

`fad809b14a2ef0814d5cb125ac4c2713ca81d962797e038857416a838c0c5cc2`

| Observation | Actual result |
| --- | --- |
| Original weight file | 269,060,552 bytes; 272 BF16 tensors |
| Complete model/environment payload | 280,269,602 bytes, 30 manifests, 95 storage chunks |
| Input validation | 31 logical inputs including Python matched their independent pins before and after |
| BEP52 acquisition | Empty receiving cache; 30 completed member fetches over actual localhost TCP |
| Shared transport accounting | One session per endpoint; 30 connections at each endpoint; no new member session or refund |
| Consumer received protocol bytes | 280,502,174; consumer sent protocol bytes 295,278 |
| Complete release readback | One admitted readback of 280,269,602 bytes and 95 chunk references; completed |
| Retention and cold recovery | TCA3 retained the received bytes; publisher and BT caches deleted; independent catalog anchor reopened; 95 chunks restored into a cold consumer |
| Typed loading and handoff | CTS1 admitted; 30 kernel-sealed descriptors carrying the same model/environment version |
| Further cache independence | Publisher, received and restored consumer caches absent before actual next use |
| Native operation elapsed | **270.246 seconds**, exit 0, under its original 300-second deadline; no termination requested |
| Actual worker | Two fresh forwards, no execution failures; owned-child exit 0 and successful wait4 reaping |

The [native receipt](model/native-result.json) binds the operation's TCV1,
TCV2 content, CTS1, BEP52 plan and CHB1 descriptor. The transport plan itself
does not contain CTS1: the outer operation independently pins both to the same
TCV1 and requires CTS1 admission before handoff. There is no provider `latest`
selection or replacement of a member during the operation.

`typed_snapshot_admitted` reports actual residency/tensor admission.
`composition_worker_executed` becomes true only after the original supervisor
and two actual forward receipts succeed. A composition-profile hash alone is
not a compatibility proof; the pinned worker implements the declared profile.

The [next-use result](model/next-use-result.json) reports a 7.596467332-second
worker observation and 11.162485 seconds of owned-child CPU. Its wait4 memory
high-water is 1,460,494,336 bytes, which is not simultaneous process-tree RSS.
The separate job cgroup peak is 3,539,898,368 bytes, including the cgroup's
process and other memory accounting. These measurements are not interchangeable.

The [two forward observations](model/next-use-observations.json) use single-token
action scoring over `[no, yes]`. Both argmax results are `yes`. The first asks
whether 8517 is greater than 8516 and is correct; the second asks whether 8517
is greater than 8518 and is incorrect. The forwards took 69,157,806 ns and
64,093,995 ns. This is actual execution evidence, not accepted model efficacy,
training improvement or a general accuracy benchmark.

Key original receipt SHA-256 values:

| Receipt | SHA-256 |
| --- | --- |
| Wrapper observation | `2eaeffa24448fdb37b02d97735f80b20dc3ff3c3148dcb6d0eefba0482c3aaea` |
| Native result | `b6f25ae1ee224ab9a619b7d7993635284495f43bc28f05f7c2b1bd8eacd4dc4b` |
| Next-use result | `a1d4948b0a904ac9d12da251222907c6cbe936f3b62fbf17a2412aa98043871a` |
| Two forward observations | `8b3c438eea2d1199aa0d753c36e5d64506f042dd6984f9f819b02273d840e242` |

## Failed observations and provenance

The [preparation archive](preparation/index.json), DA preparation archive and
Node archive retain the original failed observations. They are not upgraded
by later successes:

- The interrupted cloud snapshot build recorded rustc SIGKILL; its original
  log has no successful completion receipt. A separate snapshot attempt passed.
- The first cloud Node harness build ended with SIGKILL before tests ran and
  had an unqualified compiler-path observation. Its specific termination cause
  was not established.
- The first full DA library run passed 759 of 761 cases with two existing
  deadline failures. Their unchanged single-thread reruns passed, followed by
  the complete committed C2 crate run above.
- A V2 example preparation failed before compilation with ENOSPC. Only this
  task's reproducible build cache was removed; original logs and source remained.
- The first remote Node run passed 43 of 44 cases. The shared `/tmp` had free
  bytes but only 103 free inodes. The same binary's failing test passed in a
  task-owned ext4 temporary directory, then the complete qualified C2 run passed.
  Neither its fixture nor the provider's 64-obligation test limit was enlarged.
- The first input-migration preparation encountered an absent old source path
  before writing a spec. The successful preparation verified the new paths
  against the original independent content pins, without claiming to read the
  missing old locations.

The implementation reused an isolated, byte-verified snapshot of concurrent
capacity work at base `0746a462e80067b78317597f2fa4bacf5e3db958`; the original
working directory was preserved. Its [snapshot manifest](preparation/parallel-source-snapshot.json)
has SHA-256 `539327babdd5452ce5a28ba2c1d2f6ca70010e560f8680439342ab14a55964f7`.

## Remaining boundaries

The real operation uses **TCA3 complete-copy recovery**, not CRR2/CRG2 native
four-of-six shard recovery. The latter has its separate nine-test native
evidence. This does not prove a real 95-chunk model's funded native RS46 cycle.

The paged native profile has six fixed providers. A 95-record plan requires
at least 95 new lifetime obligations per provider plus all existing history
and enough physical shard space. Paging cannot resize an existing provider,
erase retired duties or automatically enlist additional providers.

Transport and native verification receipts describe their explicitly admitted
work. They do not meter every source-preparation read, metadata preflight CPU,
filesystem write amplification or physical network packet. The 270.246-second
native observation is not a WAN throughput benchmark.

The operation is single-operator loopback research. Python and native runtime
dependencies use an independently pinned host snapshot and are not all carried
in the sealed descriptors. Dense F32/F16/BF16 is the implemented tensor profile;
unknown quantization is refused. Independent physical custody, continuous paid
retention, M12 funding for this model operation, ordinary Hepta FinalUse,
production activation and the separate original service/campaign requirements
remain **HOLD**. Repository CI must be read separately; local passes do not
establish that every required GitHub check is green.
