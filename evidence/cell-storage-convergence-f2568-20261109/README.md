# Complete storage owner convergence: retained observations

**Development candidate; overall qualification remains HOLD / NO-GO.**

This continuation starts at the existing integration composition
`6244d34a5d9a1da993125e00facfb91a846ec489`, tree
`cc9cd341aaf0a0405bd0e85e21af6f64217c32f2`. It preserves #821, #823, #814
and #816. Only the complete-version RAM owner from #818 is selectively ported;
its incompatible discovery V3 profile is not merged.

The [component contract](../../docs/development/specs/pon/CELL_STORAGE_CONVERGENCE_DEV_V1.md)
defines the new TCA3/CPS1/CSP1/CRP1/CHB1 owners and their limits. The canonical
development plan remains the existing single project plan.

## Preparation is separate from committed-source acceptance

The initial complete source checkout passed original preflight and source
identity at exactly 6244. The following implementation preparations ran on
Linux x86_64, persistent NVMe ext4, actual Rust 1.95.0, the independently checked
OpenSSL 3.5.9 provider, CPUQuota 200%, MemoryMax 12 GiB, Cargo jobs 2 and one
native test thread. No optimization override or test-deadline relaxation was
used. These runs used uncommitted prepared source and do not certify a later
committed tree.

| Attempt | Actual outcome | Retained interpretation |
| --- | --- | --- |
| prep01 | Compile failed, Cargo 101; no native bodies executed | Two production references used undeclared `hex`; corrected to the existing `digest_hex` helper without adding a dependency. |
| prep02 | Compile failed, Cargo 101; no native bodies executed | Seven Node fixture errors: missing original Repair upload-byte field and six immutable references where the real funding owner requires mutable access. |
| prep03 DA | 709 library + 34 integration passes; 16 compile-fail doc passes | Complete default-feature DA command passed. The original child-process death observation remains in its unmodified raw output. |
| prep03 Node | 30 passed / 1 failed / 1275 filtered | Original `mandatory_expiry_per_block = 16` rejected the integrated fixture's 22 tasks sharing expiry 50. This was an actual `LIMIT`, not a passing or skipped test. |
| prep04 Clippy | Strict workspace/all-target/all-feature Clippy passed | Preparation source only, including all source available at that attempt. |
| prep05 Node | 31 passed / 0 failed / 1275 filtered | The full storage-service module passed after actual provider funding expiries were distributed to 41–46, three each; four TCA3 tasks retain expiry 50. Policy 40, CRP1 window 35, original expiry cap and all original wall/resource limits remain. |

The integrated test checks actual funding observations, task identities and
signatures with these expiries. It does not synthesize budget eligibility. Its
later source deletion/reopen path observes original completed effects and target
bytes without another debit.

The [original preparation archive](preparations01.tar.gz) is 1,162,077 bytes,
SHA-256 `b327f53a022689389d1b31a9d2c74ca56eed78ad94dc77792af18b10917b7aa5`.
All 117 original members, 4,273,301 uncompressed bytes, were reopened and checked
against [the original-file inventory](preparation-original-files.json). It keeps
the complete failed compile logs, failed Node execution, source snapshots,
argv, provider/toolchain/mount checks and successful preparation records.
No compiled binaries, model weights, mutable databases or credentials are in it.

Two convenient raw copies retain their original bytes:

- [Complete prep03 DA output](preparation/prep03-complete-da.stdout), SHA-256
  `056e0952c901adef2e1b95a539b3b510f5fed5e3b2c4946dc69f9ad0573aeb88`.
- [Complete prep05 storage-owner output](preparation/prep05-node-storage-owner.stdout),
  SHA-256 `ec430965d58be952949204c5fddcb910f4717581d19ea189d79489727b7d95d1`.

## Further integration observations

The new automatic-recovery, initial 128-chunk CRP1 and sealed-FD research
launcher/worker sources were imported together as extension07. Its first native
compile failed with Cargo 101: Rust resolved the nested execution module beside
the explicit parent path. The [original stderr](preparation/prep07-compile.stderr)
is retained unchanged (SHA-256
`ee21e97cda7c167641bbddd965c5459cf13d8350d5fe10ac2a075c2be6713027`).
An explicit `recovery/execute.rs` module path corrects that registration.
This failed observation is not a passing native run. Revised source needs its
own complete native and final committed-source gates.

Earlier 64-chunk preparations do not validate the initial published 128-chunk
CRP1 profile. Its 64-root, 2 MiB and all original TCA/M12/CPU/wall limits remain.
The actual material size motivating the new finite profile is 269,060,552 bytes
for weights alone, requiring 65 original 4 MiB chunks.

The transient preparation workspace became unavailable after extension07 was
verified and imported on the native host. Core source, original prep01--05 logs
and the complete extension07 source were already independently preserved. The workspace subsequently recovered. All fifteen original Python-control and
format observations were re-read and matched their original hashes, including
the first failed control run. Their [original archive](preparation/original-sealed-python-controls.tar.gz)
and [complete member inventory](preparation/original-sealed-python-control-files.json)
preserve the bytes; recovery is not a new execution. Fresh remote controls carry
their own outputs.

The second integrated compile also failed (Cargo 101): the external research
example called a crate-private manifest constructor. The [original stderr](preparation/prep08-compile.stderr)
remains unchanged. The example now enters the original public canonical decoder
using fields captured from the same FD, checks canonical re-encoding and retains
all independent payload and deadline checks; library visibility is unchanged.

Prep09 static validation retained one real composition failure: regenerated
source-inventory bytes still had their earlier corpus pin. Its
[original error](preparation/prep09-composition.stderr) and [complete observation archive](preparation/prep09-static.tar.gz)
remain visible. The pin is refreshed after generation; the checker is unchanged.
Repository checks, formatting, source-negative controls and the actual eighteen
Python controls passed in that attempt.

Prep10's complete DA command passed 714 library and 34 integration tests plus
16 compile-fail documentation tests. Its complete Node storage module passed
34/35, with the positive automatic-recovery control failing on a target reopen
with WouldBlock. The [original Node output](preparation/prep10-node-storage-owner.stdout)
is retained. The fixture had evaluated the reopen expression while its previous
provider owners still held their exclusive locks. The correction explicitly
drops those owners, and the original M12 budget owner, before reopening them.
It adds no retry, sleep, lock bypass or deadline relaxation.

The corrected prep12 full storage-service module passed 35 tests with 1275
filtered, using fixture SHA-256
`6f456de2dd21a5e89c181e9056561aab88fc7198738a7998370af7c7cb8d4616`.
Its [original successful output](preparation/prep12-node-storage-owner.stdout)
is 4,791 bytes, SHA-256
`98420af8831da896548021739f6f235e945ba79b729ccd9c7f153e6d68e75458`.
This success belongs to that preparation phase; the combined job subsequently
failed strict Clippy on the fixture's nested ledger return type. The
[994-byte original Clippy failure](preparation/prep12-clippy.stderr), SHA-256
`5bc0466bc32739e638c64f00e650264c6d7e5294433c9f195e7c72bbaf94545f`,
remains a failed observation.

A local `PhysicalDebitRow` type alias changes that fixture type spelling without
changing funding, ownership, locks or limits. The resulting fixture has SHA-256
`258e21b0c13030f59a1b467bb6bde612f7a74fe1a1fb0731b05e5a6f7e961601`.
Prep13 strict workspace/all-target/all-feature Clippy then passed with the
original `--locked --offline --workspace --all-targets --all-features -- -D warnings`
arguments. Its original [stdout](preparation/prep13-clippy.stdout),
[stderr](preparation/prep13-clippy.stderr) and [summary](preparation/prep13-clippy-summary.json)
are retained. The [source identity observation](preparation/prep13-clippy-source-identity.json)
binds the matching before/after source snapshot and this fixture. These separate
phase results do not establish acceptance of a later committed tree.

The [second original preparation archive](preparations02.tar.xz) is 156,092 bytes,
SHA-256 `350a1f7dc6abd844e10257582d011027fe57a364ad9e4a1d1c8b24e00983ea2a`.
Its [complete member inventory](preparations02.members.json) binds all 60 original
regular files and 4,243,308 uncompressed bytes. Integration reopened every member
and checked its exact size and SHA-256 before retaining the archive unchanged.
It preserves extension07 import records, both further failed compiles, original
patch/import inputs, the whole failed prep10 run, and both the successful
prep12 Node phase and failed prep12 Clippy phase. The first preparation archive
and all earlier failed logs remain unchanged. Private Hepta producer source,
runtime snapshots, model weights, mutable databases and keys are not included.

The [CI08 preparation archive](preparation/ci08-preparation.tar.gz) retains both
original input and output source, 17 storage CI controls, five preserved
discovery CI controls, 51 synthetic parser/configuration controls and shell/patch
checks. The new runner has 25 gates: all original 19 argv remain in order,
with complete content, retention and descriptor vectors, storage CI, full Node
storage execution and actual eighteen-name sealed-input Python controls added.
Its required new native rosters contain 70 DA and 13 Node names; these minimum
rosters do not replace full actual harness-name/count validation.

## Reproduction tools and required observations

[Tooling identities](tooling-files.json) bind the original preparation scripts,
new exact-source runner, differential runner and their pure Python controls.
The exact-source runner retains all original 19 commands and adds content V2,
TCA3, storage descriptor vectors, storage CI controls, the complete Node
storage-service module and actual sealed-input Python controls. Its immutable configuration must freeze HEAD/tree,
complete native harness names/counts and new named-test rosters. Empty or omitted
test runs cannot satisfy those checks.

The [original server fixture](controls/original-auth-server-tests.rs) has SHA-256
`cf247a21ddd167f23aff7a662eb7aa397d70c7aa58e6a0d272bf1af5cb034253`.
The differential runner separately checks three original #823 server assertion
failures, the identical candidate passes, one candidate-minus-monotonic-clamp
assertion failure and the restored candidate pass. A setup failure, compilation
failure, expired wall-clock fixture or unrelated panic is not a valid red result.

Pure Python parser controls and source/CI omission controls exercise observation
integrity. They do not execute native bodies or establish network availability.
Original release, architecture, prospective-merge, packet, History, pressure,
service, export and Hepta CI requirements remain separate and unchanged.

## Open operational boundaries

Local directories and declared provider identities do not prove independent
operators or failure domains. Native funding admission does not prove escrow,
provider payment or sustainable perpetual storage. Hash-anchored catalog history
does not defeat coordinated rollback of every journal and external anchor.
Sealed bytes and a correct handoff descriptor do not alone prove ordinary Hepta
FinalUse, an installed runtime or actual next-task execution. Any new real-model
consumer run must bind its own source and same actual sealed inputs; earlier
unrelated #821 model executions cannot be borrowed as its result.

The separate actual-model attempt01 remains FAIL / HOLD. This bundle does not
claim a completed two-forward next-use observation under the original
four-second service condition. Preparation component results do not change
that model outcome.

The original four-second service condition and separate thirty-second pressure
observation are unchanged. Public WAN, independent physical custody, perpetual
paid retention, whole-chain security, ordinary Hepta FinalUse and production
activation remain unqualified.
