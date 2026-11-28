# Bench native components

This directory is the partial HIA migration of the retained
[`trnm-bench` executable](../../../trillionnium/crates/trnm-bench/src/main.rs).
The original crate remains required. These primitives do not constitute a native
Bench CLI, a complete executor-crate replacement, a throughput result or a Node
activation.

`workload.hepta` implements the three original transaction generators.
`digests.hepta` implements both canonical SHA-256 digests. `repeat.hepta` owns the
initial native grouping and every requested replay, comparing both the digest and
the complete ordered membership. All production algorithms in these modules are
HIA instructions executed through the pinned native compiler. The Python builder
and tests transport buffers, build artifacts and observe results.

The [environment-value implementation](ENVIRONMENT.md) adds all 12 original
parsers/defaults and exact decimal conversion; [fixed formatting](FORMATTING.md)
adds native four-decimal output. These value layers preserve the same existing
scheduler contract. [Native logarithms](LOGARITHM.md),
[all 51 derived profile fields](PROFILE.md) and complete field formatting are
also implemented. [Integer/calendar text](TEXT.md) and the [complete ordered
report and persisted bytes](REPORT.md) now have native kernels and actual original
main comparisons. [Allowlisted environment selection](ENVIRONMENT.md#unix-startup-byte-selection)
projects a supplied ordered Unix startup span into the native parser. A separate
[Linux startup observer](#linux-startup-observer) validates acquisition of the
actual kernel argv bytes in synthetic processes. The real Bench CLI entry,
OS environment acquisition, complete CLI parsing and whole-package
qualification remain open. The finite [Linux executable](#linux-no-profile-executable)
runs the full default workload and real clocks, and has a bounded
[isolated profile owner](#isolated-profile-persistence).

## Linux startup observer

The [HIA startup emitter](../../platform/bench/startup_emitter.hepta) packages the
compiled [argument observer](startup_observer.hepta) behind a finite Linux x86-64
kernel entry. This is a freestanding **test observer**, not the `trnm-bench`
executable. The [builder](../../platform/bench/startup_build.py) runs the
pinned self-hosted compiler and the native emitter on captured canonical inputs.
The emitted ELF has one RX load segment, an NX stack, no interpreter, no dynamic
loader and no host implementation in its runtime. Its 376-byte literal kernel
adapter is checked with SHA-256
`6473b769cf11900af9339eeb75b5b51c61f539b0e1bdb6863991e1a840a02db3`,
followed by the exact self-hosted flat policy at ELF offset 552. That hash is
an adapter identity check, not a formal proof of its instructions.

The adapter reads the kernel's initial argc and only the argv pointer table
through its null separator. It does not dereference argv[0], envp, or auxv.
It requires 1 through 262,145 total entries, with each observed string's NUL
within 131,072 bytes and a checked sum of at most 8 MiB. These are observer
bounds, not changes to the original Bench CLI. It uses the kernel's trusted
initial argv pointers, never foreign caller-provided addresses. It measures each
string separately rather than assuming contiguous kernel storage, allocates one
private RW mapping, and checks the remaining extent before each copy and exact
completion afterward. Its three disjoint borrowed buffers occupy output [0,56),
scratch [128,1336), and input [4096,4104+argument bytes). No runtime reads files
or consults a live environment. Only the fixed 56-byte record is written; short
writes are completed, EINTR is retried and other I/O failures exit 4.

The HIA policy requires a little-endian u64 count and exactly that many
NUL-terminated arguments, preserving empty arguments, bytes that are not
UTF-8, and order. It returns `BARGV001`, count and payload length as u64 LE,
then SHA-256 of the entire input frame including the count. Shape and capacity
failures precede mutable work; the adapter exits 2 without emitting a record.
No individual raw argument bytes are printed by the observer. A digest is an
equivalence observation, not secrecy; the observer must not be used for actual
user arguments outside the synthetic qualification.

The [synthetic execve differential](../../tests/test_bench_argv_startup.py) runs
sealed Linux images with explicit synthetic vectors and environments.
Its pinned Rust reference uses `std::env::args_os().skip(1)` to observe the
original access mechanism independently, not Clap parsing. Tests compare actual
record bytes, distinguish absent/empty and reordered arguments, vary argv[0] and
envp without changing the record, cross 2 MiB aggregate, exercise the Linux
per-argument boundary and reject an excessive argc and an I/O failure.
This does not implement command syntax, help/diagnostics, timing, environment
acquisition, or the full Bench startup/process path.

## Named Linux x86-64 Bench target

With the repository's pinned HIA toolchain, compiler and compiler SHA-256
configured, build a named executable from an exact committed source:

```sh
base="$(mktemp -d)"
python3 -B -m hia.platform.bench.main_build --output "$base/output"
"$base/output/trnm-bench-hia" --txs=19 --keys=3 --determinism-repeats=2
```

Use a fresh child of an existing private directory outside the checkout.
The command emits the same static executable, full build details and a
`named-target.json` manifest binding its SHA-256 to the exact commit, selected
inputs and pinned compiler. It does not install anything or activate the
production Rust replacement. There is no build fallback or runtime Python
wrapper. Independent unbound builds of the same input are byte-identical.

Profile is refused by default. A caller who already owns a private
`isolated-source/trillionnium` directory beside the output, with an exact copy
of the checked-in `Cargo.lock`, can pass `--bind-profile-output`. Its absolute
path is compiled in (so the bound image is specific to that root); the build
does not make the profile root, follow a symlink, or accept a runtime destination.
The pre-existing profile writer and file guards still own all runtime writes.

To run the opt-in local smoke (including live report, replay and unbound
refusal) under the same pinned compiler:

```sh
python3 -B -m hia.tests.qualify_bench_named_target --output "$base/smoke"
```

## Linux no-profile executable

The [native build](../../platform/bench/main_build.py) produces a static Linux
x86-64 ELF for the **bounded Original / WriteFirst / WriteLast / HotBucketInterleave**
process, ordinary Classic AutoAdaptive, [Classic AggressiveGreedy fast path](#ordinary-classic-aggressivegreedy-fast-path), and explicitly corrected Mixed FootprintDesc. It reads real argv at
`_start`. Startup accepts either the [passive launcher names](#passive-classic-launcher-environment)
for ordinary no-profile Classic Original, or the separate HotBucketInterleave
[single-variable startup policy](#hot-bucket-startup-environment). This is an isolated candidate, not an activated general replacement
for `trnm-bench`.

Its admitted invocation is no arguments (Classic, 20,000 transactions and
2,000 keys), one each of `--txs`, `--keys`, `--read-fanout`, `--write-every`,
`--workload`, `--strategy` and `--determinism-repeats` in split
or equals form, plus one bare `--persist-profile` and, when privately bound,
one bare `--profile`. Strategy values are `original` (default) and
`write-first`, `write-last` or `hot-bucket-interleave`; ordinary Classic with
an empty environment also admits `auto-adaptive` and `aggressive-greedy`.
Explicit persistence retains
the original true default.
[The HIA argument policy](main_cli.hepta) parses full-width unsigned ASCII
decimal with one optional plus and rejects overflow, duplicates, missing
values and malformed text. Zero numeric workload counts retain the original
one-minimum normalization. The subset admits at most 20,000 transactions and
the original inclusive zero through 1,000 replays. A parsed count over 1,000
renders the exact original diagnostic and exit 2 before workload or clock
work, including with parsed values outside candidate bounds. A terminal
`--` also admits the same unmarked invocation and does not admit positionals.
The optional bare `--reader-high-water-v1` explicitly selects the corrected
scope below. Unsupported work stays closed and never falls back to Rust.

With an empty environment and nonterminal output, the same native parser and
[diagnostics renderer](main_diagnostics.hepta) reproduce the locked Rust CLI's
plain `-h`/`--help` stdout and exit 0. Recognized missing values and duplicate
options use its exact stderr and exit 2. The five unsigned options also match
the locked Rust diagnostic for empty values, invalid digits and overflow when
the value is printable ASCII within the existing 127-byte argv token extent.
Only the consumed value is reflected. Invalid printable ASCII workload and
strategy values also match the locked Clap error, including the ordered
possible-value list and optional suggestion. The HIA scorer uses the
`strsim` 0.11.1 greedy Jaro match window and transpositions, with integer
normalization producing the same binary64 round-to-nearest-even divisions
and additions in the same order. The best score must be strictly greater than
0.7 after rounding; exact ties favor the later original roster entry.
The first unrecognized positional identifier or bare long option can emit
the original unexpected-argument diagnostic. The token (including
an option's leading `--`) must fit 127 bytes; the identifier is
`[A-Za-z0-9_][A-Za-z0-9_-]*`. The long-option diagnostic uses the same
Jaro scorer over the locked command's ten long options in parser order,
including the automatic help flag. When it selects an option, the diagnostic
adds the original suggestion and that flag's specific usage, with a value
placeholder only for an option that takes a value. This does not execute or
accept the suggested option. For an unknown long option with an attached
`=value`, the complete token must still fit 127 bytes and the attached value
must be empty or printable ASCII. Only the name before the first `=` is
scored and printed, as in the locked CLI. This does not admit attached values
on boolean flags, help or the corrected-mode marker. The diagnostic may
follow a completed prefix of up to all nine original options. It shows the completed options in argv order and adds a distinct
suggested option last, without repeating an already listed option. The
original positional diagnostic uses `[OPTIONS]` even with preceding options.
Earlier errors and help retain precedence. A late unknown assignment still
elides the attached value, rather than treating it as an argument to execute.
The complete unknown argv token remains bounded to 127 bytes. After multiple
prior options, a long name of up to 122 bytes after the leading `--` leaves
six bytes in the existing private diagnostic slot for the packed roster and
its tag. Standalone and
single-predecessor diagnostics retain the previous layout and full 127-byte
echo bound. The renderer validates the packed roster and total assembled
length before writing and uses the existing literal usage fragments. Neither
the machine adapter nor the catalog changes. The first admitted error takes
precedence over later options, including `--help`, a duplicate, a missing or
invalid value, a positional and `--`. The parser verifies only the exact
remaining count, NUL boundaries, and total frame extent. It does not interpret
the suffix, and none of its bytes is added to a diagnostic. The existing
17-token process intake limit is unchanged. An original `--` preceding a token,
corrected-mode diagnostics, and malformed or nonprintable bytes in the
selected token remain refused by this candidate.
The HIA renderer reads a packed [literal catalog](main_diagnostics.json) instead of
one sequence of machine instructions per message. All these outcomes precede
scheduler, clock or profile I/O. Help comes after a syntactically admitted
prefix and takes precedence over later arguments.
The remaining grammar and option-name diagnostics outside the
bounded parser, colors/terminal output, general environments and other work
strategies remain open. The original help lists every strategy; it does not
grant admission to any unimplemented strategy in this candidate.

The three `--workload` values are `classic`, `mixed`, and `hot-streak`.
Classic ignores fanout/stride for generation but still reports normalized
configured values at full width. Mixed and HotStreak require normalized
fanout at most eight and either one normalized key or normalized write
stride at least the transaction count. This is a compatibility boundary
around the existing [reader-high-water correction](../executor/README.md#intentional-safety-correction),
not a rollback of the fix:

- With one key, a read-only transaction's required group is zero before
  the first writer and otherwise one above the latest writer group.
  The writer groups on that single key strictly increase, so the reader
  group cannot regress and replacing it with its high-water value is identical.
- With write stride at least the batch size, only transaction zero writes.
  Under Original it writes first. Under either reordering strategy any
  transactions before that writer are read-only and place in group zero.
  There is no sequence of regressing reader groups before a write.

The selected strategy ID reaches the existing native workload frame,
scheduler, replay and report in the same ELF. For WriteLast, Classic has
equal one-write footprints and retains stable ordering. Under admitted single-key interleaved
Mixed and HotStreak, WriteLast genuinely changes grouping: with 32 transactions,
stride three and fanout eight, the locked Rust and HIA WriteLast results
have 12 groups instead of 22 under Original on the same workload digest.
WriteFirst on the same workloads also has 12 groups, but its ordered
group digest differs from both Original and WriteLast. The tests compare
ordered-group digests, replay success and actual profile file bytes with the
matching original strategy, not merely its name or aggregate group count.

Without the corrected flag the default multiwriter Mixed run is **not** admitted. A real
locked Rust run and ungated HIA development run on default Mixed produced
the same input digest and group counts but different ordered group hashes:
`badb3c2b47df242068d7ed3988257e229f5a8e6f57785e037461f4432e76ed90` (original)
versus `dab1a86625487d9bd619f6c8d54af22642db79ee0134e1655e5b3fb99ced5a83`
(repaired). Arbitrary multi-key/multiwriter Mixed and HotStreak remain
refused; the explicitly qualified default dimension/strategy combinations
below are not a promise of broader equivalence. These restrictions apply
only to the isolated executable; the existing pure HIA workload and safe
scheduler components keep their own contracts.

The [native emitter](../../platform/bench/main_emitter.hepta) creates one RX
load segment and an NX stack with no loader or runtime imports. The resolved
argument, diagnostics and report code and the build-time packer use the pinned compiler's
explicit object profile; native workload, schedule, digests, profile and
environment normalization use the usual native flat profile. The build-time host transports bytes to the pinned
HIA packer, records its request/output and independently checks the result,
the address table, and the 4,480-byte Linux adapter. It does not execute the
Bench algorithms or substitute their runtime behavior.

The adapter stages at most 17 argument tokens in a private span and owns
disjoint workload, scheduler, report and scratch regions. The largest
admitted general layout has at most 180,000 raw reference pairs, requiring
no more than 3,520,136 workload bytes and 16,324,096 scheduler-scratch
bytes, below the fixed separate arenas. Profile paths and fd guards do
not change. It acquires real realtime after workload construction and
brackets only the first scheduler call with `CLOCK_MONOTONIC`. It handles
nanosecond borrow and truncates to an unsigned 128-bit millisecond count;
a clock failure never becomes a zero-duration success. Only after this call
does it hash, replay, render and publish. The ordinary no-profile path never
creates directories or files. Original and native deterministic stdout/digests match
on the default Classic, admitted default-sized single-writer workloads and
admitted small inputs; independent elapsed observations
are retained and are not compared as deterministic bytes.

### Ordinary Classic AutoAdaptive

Classic generates one read and one write on the same key for every transaction;
there are no distinct read-only accesses that could regress a writer's required
group. The existing scheduler therefore runs the original AutoAdaptive decision
against its unchanged defaults. The admitted process keeps real clocks,
membership replay and protected profile persistence. Its original 10
adaptive fields travel from the actual scheduler result to the report; only the
separately observed clocks and their derived names are normalized in comparison.
At 4,095 transactions on two alternating keys, the 2,048-point endpoint-aware
sample sees only one key. The real decision selects the hot-bucket strategy and
changes ordered membership versus Original on the same workload digest.
The locked original and HIA agree on both orders, the exact adaptive fields
and persisted file fixed points. The existing limits remain; nonempty startup
environments, AutoAdaptive on Mixed/HotStreak, the explicit corrected marker
with AutoAdaptive are not admitted here.

### Ordinary Classic AggressiveGreedy fast path

An unmarked Classic invocation may select `aggressive-greedy` when the process
environment is empty. With a qualified private profile root, the same strategy
can also request `--profile` through the existing file owner. The workload emits the
existing executor strategy word 6 with the original effective defaults
(flags 6, deep-scan bit clear); the process does not rewrite it as Original.
The retained Rust fast path and the HIA scheduler take the same dependency
placement for Classic, which reads and writes one object per transaction.
The locked original and HIA are compared on the full output excluding only
independently checked elapsed time. A separate arithmetic model verifies both
digest domains and ordered assignment across distinct workload dimensions.
The existing zero-through-1,000 replay range and 20,000-transaction cap still
apply. The actual profile runs retain the original AggressiveGreedy label,
dependency checks/hits and zero deep-scan stage counters, with full stdout
and the file extent fixed point checked against the locked original. The
profile path, filename, clocks, file guards and write contract are unchanged;
an unbound image still refuses profile execution. Deep scan and its tunables,
nonempty environments, corrected mode, Mixed and HotStreak remain outside
this candidate scope. There is no new file destination or fallback.

### Corrected workload qualification

The test-only `reader-high-water-v1` suite creates a private exact Git archive
of the Cargo tree and builds it with the original lock. Exactly four reader
table updates in the private Rust executor retain the larger reader group.
No tracked Rust source, workload, profile code, or lock changes. The old
experimental group digests above remain historical comparisons; this
corrected oracle is a distinct semantics target, not old Rust byte parity.

The qualification compares ordered group membership, raw and rendered profile,
the two digests and replay against that actual private Cargo CLI and adapter.
An independent access graph checks every transaction exactly once and denies
overlapping writes/reads in each group. The component-level formatter comparison receives the oracle's actual clock
and path fields; the separate standalone comparison below checks the native
clocks and file behavior directly. The standalone ELF admits these exact multiwriter
defaults only with an explicit bare `--reader-high-water-v1` and an empty
environment: 20,000 transactions, 2,000 keys, fanout 3, write every 1, and
Original or WriteFirst order (Mixed or HotStreak), or
HotBucketInterleave (HotStreak only).
Existing already-admitted Mixed/HotStreak shapes can also be explicitly
marked; no Classic, arbitrary new multiwriter shape, or nonempty environment
is admitted by this flag. Workload and replay limits are unchanged.

The explicit mode also admits `--strategy footprint-desc` on exactly the
same 20,000/2,000/fanout-3/stride-1 **Mixed** shape with an empty environment.
FootprintDesc orders the union of read and write object domains by descending
unique width, then transaction ID. This fixture has 19,960 width-four
transactions and 40 width-three transactions. Both the locked corrected Rust
oracle and the native ELF produce a different ordered grouping from Original
and WriteFirst for the same workload digest. The [whole process
differential](../../tests/test_bench_footprint.py) checks the independent graph,
profile bytes and real file effects, separate clocks, replay, and refusal of
all unmarked, nonexact, and nonempty-environment FootprintDesc invocations.
This is not support for ordinary FootprintDesc or its other workload shapes.

The same ELF takes real clocks, runs the real native scheduler and replay,
renders `schedule_semantics=reader-high-water-v1` in stdout and the
persisted profile, and uses `executor-profile-summary-reader-high-water-v1-`
as a separate filename prefix. The old profile path and unmarked output
are unchanged. The full differential compares exact profile fields with the
corrected Rust CLI independently of real clock/path differences and confirms
each actual output file byte with its corresponding stdout and fixed-point
metadata. Existing workload/replay limits and file protection remain.
The test also exercises the largest existing bounded 20k-by-fanout-8
arena and the 1,000-replay bound on a small workload. This flag does not
change a signed domain or replace any production entry.

Run `python3 -m unittest hia.tests.test_bench_reader_high_water -v` with the
pinned HIA toolchain and cached original locked Cargo dependencies. An
[independent workflow](../../../.github/workflows/hia-bench-corrected-evidence.yml)
runs the same four methods on the exact source, without changing the General
job or its legacy Bench carrier. It retains a separate ZIP containing only
allowlisted synthetic request/response, CLI and profile streams, their
checksums, exact commit/tree/run/attempt and the actual test-start/finish
receipt. The reader rejects extra, missing, linked or oversized entries,
binds raw native calls and effect bytes to the corrected locked Rust oracle,
and checks ZIP CRC on read. Ambient environment data, build directories and
private compiler binaries are not retained. A local focused receipt does not
substitute for a hosted run or General qualification.

### Passive Classic launcher environment

The default Classic Original executable can run with a finite set of passive
launcher names without stripping them. It accepts at most 64 entries named
exactly `PATH`, `HOME`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TERM` or `TMPDIR`, only
when unmarked, without profiling and with zero requested replays. The adapter
stops each entry at its first equals sign, so values are neither read nor
copied, even when empty, duplicated or non-UTF-8. Only zero-padded name words
reach the HIA admission check. Output and no-file effects match the locked Rust
entry under this finite environment; there is no general loader/environment
compatibility claim. Other names fail closed before workload or file work.

### Hot bucket startup environment

WriteFirst, WriteLast, AutoAdaptive, and Original outside the passive slice
continue to refuse nonempty environments without dereferencing their values.
The corrected mode and plain diagnostics keep their existing empty-environment
fences. HotBucketInterleave admits an
empty environment or at most 64 actual Linux environment entries, each
beginning with the exact case-sensitive `TRNM_HOT_BUCKETS=` name. A missing
equals sign, prefix collision, unrelated key, or extra entry fails before
workload construction, clocks, or file creation. For an allowed duplicate
name the first value wins, even when invalid UTF-8 or empty: later value
bytes are not read. The selected entry may use the Linux x86-64 131,072-byte
NUL-inclusive single-entry limit. The adapter checks names only up to the
first mismatch; it does not copy or inspect unrelated values.

Only the selected value enters a private one-field frame for the unchanged
[native parser](environment.hepta). That parser preserves the original
normalization, default of 8 and clamp to 4–64. The entry wipes the staging
frame and parser scratch, then supplies the numeric result to the checked
scheduler frame before any workload digest or timing. No raw environment
is part of reports, profile files, or the test evidence. Every replay uses
the same effective value. This does not implement general startup environment
capture or the other 11 getters as process inputs.

A synthetic actual-process differential against the locked Rust executable
uses unchanged 64-transaction Classic and admitted single-writer Mixed and
HotStreak workloads. Values 4, 8, 17 and 64 produce four distinct ordered
group digests for each workload while its input digest stays the same.
It also checks first-match/invalid/empty handling, a full-width environment
entry, exact profile output, and refusal above the 64-entry bound.

### Replay ownership in the Linux process

The entry invokes the real scheduler once inside the clock, retaining that
result and its initial group hash. Each additional requested call invokes
the same scheduler on the same immutable workload, with a separate bounded
result region and the scheduler's ordinary per-call initialization. Only
after a validated replay obtains its own canonical digest does the owner
check its digest, transaction/group counts and every ordered group offset
and member word. Raw profile fields are not part of replay membership.
The initial scheduler result, clock and profile remain unchanged.

A mismatch exits 2 using the original input-hash diagnostic before ordinary
stdout or profile-file creation. At zero replays the report says
`determinism.replay_match=not-requested`. The unchanged locked Rust CLI
differential includes real no-profile and persisted-profile replays, plus
1,000 replays of a small finite workload. This is not a maximum-scale
throughput or elapsed-time acceptance statement. The separate synthetic
leaf-linked fixture, which is not the supported executable, independently
counts real native calls (including zero before the bound, and 1,001 at
the maximum replay count), puts real delays after replay callbacks to
verify the clock exclusion, and exercises separate ordered-membership
and digest mismatches even when the other comparison still matches.

### Isolated profile persistence

The same Linux entry additionally accepts one bare `--profile` only when
the build binds a private `isolated-source/trillionnium` directory inside
its output scope. With no binding, it rejects the flag before work. The
runtime accepts no output path from argv, environment or stdin. The real
anchor is compiled into the image; test setup verifies the exact locked
Cargo sources by copying the tracked tree to that isolated anchor and
compiling the unmodified original there. Both implementations use that
anchor's `run/bench` and the original timestamp-derived basename.

The native owner copies the first schedule's 17 raw profile words, calls the
native 51-field profile and complete report components, and attempts real
directory and file operations. Directory handles confine publication to
the anchored directory. New files open with exclusive creation; before
truncation the opened descriptor must be a single-link regular file.
Native opens are nonblocking and do not follow symlinks. The private build
root must remain under one owner's control with serialized writers and no
concurrent pathname/link changes. Symlink, hardlink and FIFO refusals are
**candidate-specific** confinement, not claimed Rust equivalence.
Recognized Linux errors retain their observed output ordering. A directory failure appends only the error. A file-stage failure
preserves path and basename first, then appends the error, with no false
success claim for the created file. If some bytes were written before an
error, the real partial file remains. Outside the recognized Linux error
domain, the bounded owner refuses rather than inventing an error.

The [differential](../../tests/test_bench_main.py) retains exact stdout,
stderr, each observed file and the two independent clocks. It compares
both actual processes' complete deterministic profile fields and validates
every timestamp-dependent field before normalization. In particular it
checks the same-second overwrite and truncation, file self-described line
and byte fixed points, real ENOTDIR, EISDIR and short-output EFBIG under an
isolated file-size limit. Ordinary Clap invalid-input diagnostics and
unqualified OS/platform behavior remain distinct. No old package is
retired; no live Bench output is touched.

## Original observable contract

### CLI and normalization — CLI remains OPEN

The original is a Clap-derived executable with the following long options:

| Option | Default | Original behavior |
|---|---|---|
| `--txs <usize>` | 20000 | Normalize zero to one after parsing |
| `--keys <usize>` | 2000 | Normalize zero to one after parsing |
| `--read-fanout <usize>` | 3 | Normalize zero to one; printed even for Classic |
| `--write-every <usize>` | 1 | Normalize zero to one; printed even for Classic |
| `--workload <value>` | `classic` | `classic`, `mixed`, `hot-streak` |
| `--strategy <value>` | `original` | Seven names listed below |
| `--profile` | false | Add the complete profile report |
| `--persist-profile` | true | A SetTrue flag; no CLI false-valued counterpart |
| `--determinism-repeats <usize>` | 0 | Reject values over 1000 before generating work |

The retained Clap front end defines help, strict options and all parse errors.
The [native qualification](../../tests/test_bench_main.py) compares real stdout,
stderr and exit status for plain help, terminal `--`, and the admitted strict
missing-value, duplicate and printable numeric/enum value families against the unmodified, locked Cargo binary.
A binary request frame is not a substitute for this layer. In particular,
`--persist-profile=false` does not disable persistence in the retained CLI.

The explicit repeat-limit error is
`--determinism-repeats exceeds bounded maximum 1000`, written to stderr with exit
status 2. A grouping replay mismatch also exits 2 before printing the accumulated
normal report. Successful normal execution exits 0.

### Workloads — implemented

All generated transaction IDs are their zero-based input indices. Every reference
has version 1 and every payload is empty. Access-list order and repeated references
are part of the workload digest, even though the scheduler deduplicates domains.

| Workload | Read references for transaction `i` | Write references |
|---|---|---|
| Classic | One reference `i % keys` | The same reference, on every transaction |
| Mixed | In order, `(i + 7*j) % keys` for `j` in `0..read_fanout` | `(13*i + 3) % keys` when `i % write_every == 0` |
| HotStreak | First `(i / 16) % keys`; each later side read starts at `(i + 11*j) % keys` and advances modulo `keys` while it matches an earlier read, with at most `keys` probes | The first hot reference when `i % write_every == 0` |

HotStreak retains the requested number of reads when the keyspace is exhausted;
references can therefore repeat when fanout exceeds key count. Classic ignores
fanout and write stride when constructing transactions, but the original report
still prints the normalized configured values. Its effective profile values are
one read and write ratio 1.0.

### Scheduler and environment — native configuration values implemented

The seven strategies are `original`, `footprint-desc`, `write-first`, `write-last`,
`hot-bucket-interleave`, `auto-adaptive` and `aggressive-greedy`. Printed names are
Rust Debug spellings: `Original`, `FootprintDesc`, `WriteFirst`, `WriteLast`,
`HotBucketInterleave`, `AutoAdaptive`, `AggressiveGreedy`.

The existing [HIA scheduler contract](../executor/README.md) defines transaction
ordering, its 17 raw profile fields and its 10 adaptive-decision fields. Its
reader-high-water correction is intentionally retained. A later reader must not
replace a higher reader group with a lower one. This correction can alter group
membership and counters even for an original result that happened to be safe.
The Bench tests execute the unchanged Rust library, record each difference,
require the repaired independent reference and separately check the conflict
graph. They do not make the original unsafe result an acceptance target.

The original scheduler reads these process environment variables:

| Variable | Default | Effective restriction |
|---|---|---|
| `TRNM_AGGR_DEEP_SCAN` | false | Toggle parser |
| `TRNM_AGGR_SKIP_EMPTY_STAGE_CHECKS` | true | Toggle parser |
| `TRNM_AGGR_SCAN_ROUND_ROBIN` | true | Toggle parser |
| `TRNM_AGGR_SCAN_WINDOW` | 0 | Grouped unsigned integer, maximum 4096; zero is unlimited |
| `TRNM_AGGR_SCAN_RR_SEED` | 0 | Grouped unsigned integer, full usize range |
| `TRNM_HOT_BUCKETS` | 8 | Loose unsigned integer, clamped to 4..64 |
| `TRNM_AUTO_MIN_BATCH_LEN` | 512 | Grouped unsigned integer, clamped to 64..4096 |
| `TRNM_AUTO_SAMPLE_LEN` | 2048 | Grouped unsigned integer, clamped to 64..2048, then limited by actual batch size |
| `TRNM_AUTO_HOT_STREAK_RATIO` | 0.22 | Finite parsed binary64, clamped to 0..1 |
| `TRNM_AUTO_REORDER_MIN_MARGIN` | 0.04 | Same |
| `TRNM_AUTO_REORDER_MIN_HOT_KEY_SHARE` | 0.0075 | Same |
| `TRNM_AUTO_MIN_EXPECTED_GAIN_SCORE` | 0.01 | Same |

Missing, non-Unicode, empty or invalid environment values fall back to their
respective defaults. Numeric parsers trim Rust Unicode whitespace and optionally
one matched single- or double-quoted pair, trimming its interior. The loose
integer parser removes underscores and commas and allows one leading plus.
Grouped integers remove underscores, allow one leading plus and accept commas
only when every segment after the first has exactly three ASCII digits. The
first segment is not restricted to three digits.

The float parser removes underscores; accepts percent suffixes; distinguishes a
single decimal comma from a thousands comma using the original zero-prefix and
three-digit rules; validates repeated grouping commas; parses the normalized
text as Rust binary64; rejects nonfinite values; divides percentages by binary64
100; then clamps. Negative zero is preserved. This contract requires precise
text conversion, not a host-side configuration approximation.

Toggle parsing trims whitespace and one matching quoted pair, lowercases ASCII,
and treats empty or all-underscore/comma strings as default. Exactly `0`, `false`,
`off` and `no` are false; every other nonempty value is true.

### Digests and replay — implemented for canonical Bench transactions

Input SHA-256 starts with `TRNM-BENCH-INPUT-V1\0`, followed by each transaction:
ID as u64 LE, read count as u64 LE, ordered `(object ID, version)` u64 LE pairs,
write count and ordered write pairs, payload length as u64 LE, then payload bytes.
There is no transaction-count word in this digest.

Group SHA-256 starts with `TRNM-BENCH-GROUPS-V1\0`, followed by group count as u64 LE.
For each ordered group it hashes its zero-based group index, member count and
ordered transaction IDs, all u64 LE. Bench transaction IDs equal input indices,
so the scheduler's returned index array is exactly the ID sequence hashed here.
Hex text output is lower case; the primitives return the equivalent 32 raw bytes.

Zero requested repeats means `determinism.replay_match=not-requested`. Otherwise
the original performs precisely that many additional schedule calls after the
initial call. Each replay must match both the SHA-256 digest and every ordered
member vector. A digest alone is insufficient. The HIA owner executes this loop
itself; Python test loops are not the implementation.

### Timing/report ownership — OPEN; derived profiles and formatting implemented

The original captures SystemTime after workload construction. It times only the
first scheduler call with Instant. Digest generation, all deterministic replays,
derived metrics and persistence occur after the timed interval. `elapsed_ms` is
the integer millisecond count. Times before the Unix epoch use zero; ISO text uses
the original `civil_from_days` routine and UTC `Z`, with minimum-width numeric
fields. Timing and the capture stamp remain real observations, never fabricated
constants in equivalence tests.

Normal stdout begins with `bench_parallel_grouping` and, in order, workload,
strategy, normalized transaction/key/fanout/stride values, persistence flag,
estimated conflict rate, group count, grouped count, elapsed milliseconds,
input hash, groups hash, requested repeats and replay status. Each line ends in
LF. Booleans are lowercase; workload names use `Classic`, `Mixed`, `HotStreak`.

With `--profile`, the report additionally contains:

- Workload/strategy/configuration, effective reads and write ratio, workload
  signature, persistence flag, capture epoch and ISO, capture-stamp family and
  repeated epoch fields, elapsed time, estimated conflict rate, coverage,
  ungrouped count, completeness, groups per 1000 transactions, grouping
  efficiency and the literal persisted-profile-capture hint.
- All 17 raw scheduler profile fields in declaration order.
- Conflict-hit ratio; checks, hits and candidate groups per transaction;
  reused placements and their share; new-group share; retry pressure;
  fallback shares relative to transactions, new groups, retry hits, scans and
  retry misses; candidate groups per retry hit and reused placement; retry reuse,
  salvage and hit rates; scan misses, miss rate, misses per transaction/group and
  overhang per retry hit/reused placement.
- Per-stage WW/WR/RW hit rates, hits per transaction and retry shares; dominant
  stage (`none`, `mixed`, `ww`, `wr`, `rw`), dominant share and attributed share;
  dominant lead hits and its two shares; attributed and unattributed hits/shares;
  attribution coverage; overlap hits and its shares; singly attributed hits and
  its shares; stage concentration and normalized stage-mix entropy.
- For AutoAdaptive only, all 10 adaptive fields, including exact reason text and
  binary64 threshold, margin, hot-share and expected-gain values.

Ratios with a zero denominator return positive zero. Counts use the original
saturating differences where specified. Attributed retry hits are the ordinary
sum of the three stage counters; dominance ties produce `mixed`. Concentration is
the sum of the three squared retry shares. Entropy skips zero stage weights and
computes `sum(-p * ln(p)) / ln(3)` using attributed hits as its denominator.

The estimated conflict rate is binary64 `1 - min(keys/n, 1)`; this must not be
silently replaced with `(n-keys)/n`, whose rounding can differ. Groups per 1000
transactions multiply by binary64 1000 before dividing. Every displayed float
uses the original fixed four-decimal formatting and operation order. The current native profile composition includes the required signed arithmetic,
natural logarithm and exact output formatting. Its separate contracts retain
operation order, overflow behavior and numerical qualification; they do not
substitute for actual OS time or complete report/persistence ownership.

### Persistence — isolated candidate; general owner OPEN

Persistence runs only when profiling and the persistence flag are true. Its
default directory is the original compile-time Cargo manifest directory joined
with `../../run/bench`. The file name is
`executor-profile-summary-{capture_started_at_epoch}.txt`. Same-second runs
replace that file using the original `fs::write` behavior.

The implementation creates directories recursively, attempts directory
canonicalization, then appends `profile.report.path` and
`profile.report.artifact_basename` to the output lines. It clones the lines and
iterates the persisted `profile.report.output_line_count` and
`profile.report.output_bytes` values to a fixed point. Those last two metadata
lines are present in the file, not the stdout line vector. The file contains a
final LF, and byte length counts UTF-8 bytes.

Directory-creation failure happens before the path lines are appended. Write
failure happens after those lines. Either error appends
`profile.report.persist_error={original I/O error display}` and normal stdout
continues without changing the successful process exit status. Canonicalizing
the final file falls back to the original output path. A native owner must retain
these ordering, replacement, failure and path-display contracts.

## Native buffer contracts

All words are unsigned u64 LE. Borrowed input, output and scratch live extents
must be exclusive and must not overlap. Caller pointers may be unaligned. There
is no new transaction, key or fanout ceiling: checked arithmetic and the actual
buffer extents bound each call. Existing SHA full-length helpers enforce the
SHA-256 bit-length representation limit; the legacy 2,098,176-byte default SHA
entry is not used.

### Workload `f0(input, output, scratch) -> u32`

Input is exactly 64 bytes: magic `BNCHGEN1`, workload 0..2, transaction count, key
count, fanout, write stride, strategy 0..6, and a zero reserved word. Counts are
normalized as described above. Output is an eight-byte length followed by a
complete `EXSCH001` schedule request with the scheduler's default effective
configuration. If R is the actual reads per transaction and W is the number of
writing transactions, total required output is `136 + 32*N + 16*(N*R + W)`.

Codes are 1 for wrong input length, 2 for wrong magic, 3 for workload/strategy or
reserved-word errors, and 100 for capacity or capacity-arithmetic failure. These
refusals leave output and scratch unchanged. Success writes exactly the declared
prefix and leaves all scratch unchanged.

### Digest `f0(input, output, scratch) -> u32`

The input is either an exact `EXSCH001` request or an exact `EXSCOUT1` schedule
result. Request hashing preserves raw list order, duplicates, versions, IDs and
payload. Result hashing preserves the ordered Bench IDs represented by indices.
It checks framing, group offsets and final member count before mutable work.
Output requires 32 bytes and scratch requires 1208. Code 1 is invalid framing;
code 100 is insufficient output/scratch. Those errors are atomic. Success writes
32 output bytes and uses only the 1208-byte SHA arena.

### Repeat `f0(input, output, scratch) -> u32`

Input uses schedule-request layout with magic `BNCHREP1`, operation zero, repeat
count 0..1000 at offset 112 and zero at offset 120. All other effective scheduler
configuration fields retain their original validation. Let `B = 264 + 16*N` and
`S = 4096 + 168*N + 72*M`, where M counts raw reference pairs. Output capacity is
`2*B + 112`; scratch capacity is S.

The first output region is the current scheduler result. At offset B, six words
contain magic `BNCHRES1`, requested repeats, match state (0 not requested, 1 match,
2 mismatch), actual schedule execution count, first-result byte length and first
group count. Input and first-group digests occupy B+48..B+112. A saved first
schedule result starts at B+112. It is disjoint from every live scheduler write.
Unwritten gaps and trailing bytes remain unchanged. Every replay resets the
scheduler arena before its next use; SHA state never survives as scheduler state.

Codes 1/2/3/100 reject frame, magic, config or capacity before output/scratch
mutation. Within-transaction version skew has the existing scheduler code 5
(output unchanged, parsing scratch may change). Code 6 reports an actual replay
mismatch. The snapshot and metadata are private to the call, not trusted cached
external memory. Only ordered groups and their digest participate in the replay
comparison; raw profile telemetry is excluded, matching the original check.

## Reproducible qualification and remaining boundary

The [builder](../../platform/bench/build.py) captures canonical function bodies,
actual compiler input/output, pinned compiler identity, preflight dependencies,
original crate sources and build receipts. Both object and shared artifacts use
the canonical `toolchain.build_native` entry with the explicit component includes;
their real receipts bind the exact compiler wire and source inputs. Tests create
standard `NativeModule` instances and require their independently rebuilt images
to equal the retained builder artifacts. The general qualification recorder sees
both the direct builds and the module initializations and calls. The comparator
probe has an explicit generated-fixture test owner and preserves unchanged
canonical dependencies. Every build and test target lives outside the repository.

Run [the formal tests](../../tests/test_bench_native.py) with the existing explicit
HIA toolchain/compiler pins and a fresh `HIA_BENCH_OBSERVATIONS` directory:

```bash
python -m unittest hia.tests.test_bench_native -v
```

The Rust adapter uses `include!` on the unmodified original Bench source and
links actual Cargo-produced dependencies. The suite also runs all 11 retained
original tests and the real original CLI repeat path. It covers all workloads and
strategies, zero normalization, duplicates and side-read exhaustion, stable
hashes, known scheduler correction differences, replay counts 0/1/3/1000, malformed
and undersized buffers, comparator negative controls, default 20,000-transaction
workloads, inputs exceeding 2 MiB, physically unaligned buffers and sequential
arena reuse. Hash, membership, output-tail, input and arena guards are checked.

The environment byte selection and text parsing, derived profile methods and
entropy, four-decimal formatting and ordered report have separate native
qualifications. The CLI parser, OS environment acquisition, clock capture and
persistent-file owner remain OPEN.
The original `trnm-bench` package and executor dependency must remain until those
contracts and their complete real-original qualification are closed.
