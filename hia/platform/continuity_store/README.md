# Native typed staging with finite installed continuity

This unit adds the complete non-PQ relationship calculation of
`continuity_v1::check_state` to the private native TypedStore execution path for
four internally constructed installed configurations. The HIA code reads the
actual staged file descriptor, builds the complete sorted State index, performs
exact point lookups, checks maintenance and all liabilities, and validates the
applicable capacity relation. The hosted process supplies I/O capabilities and
qualification input data; it supplies no account-membership answer, imported
reward count, expected State root, or validation-success bit.

The resulting file is a private staging observation. This unit has no namespace
publication, durable Node transaction, COMMIT, active-record, event/outbox, or
caller-visible Node ACK authority. The storage owner and this finite stage are
not yet a complete persistent Node.

## Original call boundary

The selected order is the prefix of the original fast-activation operation in
`trillionnium/crates/trnm-pon-node/src/store.rs`:

1. `apply_delta_with_progress`, including original before/after and detach rules.
2. Complete `slot_state_with_progress`, including final callback success.
3. `continuity_v1::check_state` on that materialized next State.
4. The next operation-local progress callback.
5. Optional classical `pon_executor::root`.

The actual fast-activation caller subsequently performs its selected commitment
checks and transaction operations. Those namespace, expected-root, commitment
cache, prior/active record and publication decisions are not supplied here.
Historical replay checks the historical commitment before continuity; the reorg
tail has another callback before continuity. This unit is not a replacement for
all Node call paths.

For the growth constructors, a selected root would be GSC2 through
`root_for_config`, not the classical M06 root. A growth request with the classical
root flag set is refused before progress or file mutation. Growth continuity
qualification uses `root=false`; GSC2 and the complete growth commitment path
remain unimplemented in this unit.

## Finite configuration domain

All four constructors use the installed `linear-expert-dev-v1` model and the
installed genesis timestamp. The actual original adapter uses
`Settings::development_with_profiles(None, policy, task)`, compares its params,
network and parameters with `Config::installed_with_profiles`. All four use the
original `Node::open(..., 1)` and `StateBackend::Legacy`. The growth-reference task
in variants 2 and 3 selects its complete-State capacity and commitment rules.
`PermanentAccountGrowthV2` requires a separate Settings transformation and is
outside these four installed constructors.

| Variant | Installed policy | Installed task profile | Root option |
| --- | --- | --- | --- |
| 0 | legacy-first-two-v3 | consensus-maintenance-continuity-dev-v1 | classical or omitted |
| 1 | native-public-evaluation-dev-v1 | consensus-maintenance-continuity-dev-v1 | classical or omitted |
| 2 | legacy-first-two-v3 | consensus-maintenance-growth-reference-dev-v2 | omitted |
| 3 | native-public-evaluation-dev-v1 | consensus-maintenance-growth-reference-dev-v2 | omitted |

`source-inputs.json` names the eight original installed JSON files. HIA embeds
their exact bytes and performs the actual canonical-value encoding, policy and
registry hashes, ordered params/ledger/work/model parameter hash, final
chain-label network hash, complete 4,096-cell matrix generation, task/model/input
hashes and complete maintenance-record construction. Public evaluation overrides,
continuity configuration, growth configuration and the public storage suffix are
applied in the original order.

The original accepted configuration domain is broader and state-dependent. For
any `Config` whose task profile is neither continuity nor growth,
`check_state` returns success immediately; this native entry has no constructor
for that case. For enabled configurations, the original function checks the
maintenance record built from that Config and then its capacity relation,
including any u64 `reward_maturity_blocks`, its public-evaluation selection,
growth selection and PQ retained-reward rules. It does not restrict its input to
the four constructor names above.

Within the non-PQ domain, the difference from this native domain therefore
includes disabled task profiles, other valid installed policies or models,
timestamp/network/parameter overrides, other maintenance policy values,
different reward maturities and other accepted configuration combinations.
Fields that the original continuity relation does not inspect can also differ.
The four variants are a finite subset; refusing another variant is this entry's
declared domain boundary and is not evidence that the original Config was
invalid or that all non-PQ Configs have been ported.

The four installed constructors internally establish that native PQ is absent,
and the actual Rust adapter independently checks that fact. No caller-provided
`non_pq` flag or imported reward count is accepted. PQ configurations, private
migration anchors, retained rewards and their relationship validation remain
unimplemented. The supplied height is a function argument; authenticating it
against a persisted Node record belongs to the missing outer owner.

## Complete State relation and ordering

The frozen TypedStore owner retains its full Delta materialization and complete
slot-state pass. It preserves all original row progress boundaries, String/JSON
materialization order, duplicate Delta handling, before/after errors, canonical
serde roundtrip restrictions, original 160-byte key and 4,096-byte stored-value
bounds, and the classic/growth row-count bounds. No 1 MiB or 196,608-byte total
State cap is added.

Only after the final complete-State callback succeeds does private dispatch
4097 enter the continuity kernel on the actual output FD. It independently
checks the regular-file identity and extent, scans all rows, requires exact
sorted unique keys, counts all `account:` keys and records every row offset.
There is no caller-supplied hash table or precomputed key index.

Maintenance is checked first. Since the entire slot has already passed the
original canonical serde readback constraint, byte equality with the complete
fixed expected maintenance value preserves Value equality here. Integer zero
and floating zero remain different. Bad stored JSON, noncanonical spelling or
a Delta mismatch can fail before maintenance; a continuity failure precedes
the optional classical root's number/ASCII restriction.

Liabilities are processed in original lexical namespace order:
`contribution:`, `quota:`, `release:`, `reward:`, `task:`. Malformed,
empty, NUL and Unicode suffixes remain included exactly when their prefix
matches. Contributions reserve an archive only for public evaluation, by exact
`evaluation-archive:<suffix>` key existence; that value is not interpreted.
Positive remaining values require a valid 64-character lowercase hexadecimal
owner. Zero remaining ignores the owner entirely. A matching account key
counts as present even if its stored value is null or has another schema.

For rewards, the native calculation preserves maturity parsing, the
`due <= height` short circuit, checked upper-bound arithmetic, duplicate-due
rejection, amount parsing and owner lookup in the original order. Amounts are
validated, not summed. After all rows, it checks the full expected due set and
queue reserve. It does not substitute a reward-row count for the exact due set.

Missing recipients are retained as their complete 32-byte identities, sorted
and deduplicated by native code. Exact point lookup reads the same actual State
FD and uses the native complete row-offset index. A digest collision cannot
manufacture membership. Classic required keys include every reserve. Growth
separately checks at most 1,000,000 permanent accounts including reserves and
at most 65,536 working keys including archive and reward-queue reserves.

The public `capacity_with_progress` interface deliberately visits every State
row and has a different callback contract. Optional AccountPointAccess callbacks
and separate monetary-certificate views also have additional contracts. These
interfaces are not claimed by the ordinary `check_state` entry implemented
here.

## Native composition and ownership

Four HIA-compiled images perform the primary stage, classical root, continuity
relation and installed-context construction. Each keeps the existing compiler
profile of at most 128 functions, 8,192 operations and 1 MiB emitted image. A
separate HIA emitter produces the Linux ELF prefix and syscall dispatch; the
hosted link action concatenates those exact images. The composed ELF can exceed
1 MiB without raising any per-image compiler limit.

Private dispatch 4097 and context dispatch 4098 are scheduler states inside that
ELF. They are not imported validation receipts or public COMMIT capabilities.
The complete continuity result must be produced before callback kind 8, and that
callback must succeed before any requested classical root phase.

The primary arena retains the TypedStore layout. The additional 80 MiB arena
contains complete 64-byte recipient records, a 64-bit row-offset table for
1,065,536 rows, bounded key/value transfer buffers and private context material.
The final recipient swap slot ends below the index; the final index entry ends
below metadata. The native owner does not allocate a Python/Rust State map.

TypedStore admission still requires sealed immutable inputs and a private
regular output with the correct UID, mode, link count, access mode and flock.
Progress/control capabilities must be distinct real FIFO/pipe objects with
write-only/read-only rights, no O_PATH and no file alias. All those gates run
before the first callback. Continuity performs actual fstat/pread on the same
output capability and rechecks its identity.

Ordinary refused operations discard their staged output through the native
cleanup path. Explicit operation cancellation keeps its class/token and does
not acquire State-corruption authority. SIGKILL or a lost result channel may
leave a private staging file; neither condition produces a Node ACK or grants
publication rights. Fresh-process reread is tested separately from OS cache
eviction, power loss or protection against a continuously active same-UID
attacker. Those stronger claims are not made.

## Qualification and retained observations

Run the actual native source-bound suite from the repository:

```sh
python3 -B -m hia.platform.continuity_store.qualify --output /tmp/continuity-native
python3 -B -m hia.platform.continuity_store.test_integrity --output /tmp/continuity-integrity
python3 -B -m hia.platform.continuity_store.capacity --output /tmp/continuity-capacity
```

The ordinary native suite keeps 572 semantic inputs: the original 536 inputs,
12 combined slot/Delta/cancellation boundaries and 24 working-capacity cases.
It also executes 13 direct native context ABI controls and 74 physical owner
controls. The context checks use actual HIA-emitted native object code under the
guarded shared ABI at exact minimum buffer sizes and with output-tail guards.
Their four complete snapshots are compared with the actual original installed
constructors during original Rust qualification.

Complete control and comparison records are written incrementally to journals.
The in-memory report retains compact summaries and exact journal offsets,
lengths and hashes. Final comparison JSON contains all original result bytes.
The controller verifies the entire journal while assembling that JSON and
retains both physical output files and the full control archive. This bounds
retained controller memory without reducing the corpus, output checks, original
native arena or deadlines. Linux process memory observations accompany each
stage. A prior exit 137 is retained as an interrupted run with unknown cause;
it is not relabeled as OOM or as a completed qualification.

`rust_oracle.py` validates the exact complete native source closure and the
entire source-defined ordered corpus before looking up Cargo, copying sources
or running original code. Missing, extra, changed, escaping or symlinked source
inputs are refused. Corpus names, order and actual bytes are checked; XZ input
has a decoded-size bound and rejects truncation, trailing bytes and extra streams.
The negative integrity suite uses explicitly labeled controller fixtures and
performs no native or Rust semantic execution.

The actual original adapter appends a cfg(test)-only child module to a private
copy of the original store. It uses the real SQLite transaction,
apply_delta_with_progress, slot_state_with_progress, check_state and optional
classical root. It retains original error text, callback attribution, owner-stop
classification and exact rollback bytes. It executes all 572 cases and four
retained original tests, verifies the actual locked serde_json 1.0.149
default/std artifact and preserves all original production function bytes.
A compile-only or source-only observation is never an original-Rust PASS.

The separate growth-capacity controller streams a physical 1,065,536-row file,
performs a fresh-process complete reread from the actual produced output, checks
the final-byte and row-count boundaries, checks each growth partition limit,
and sorts 65,515 distinct recipient identities. Its million-account fixture
uses both the first and the last account key as real recipient lookups. This is
a maximum-row/index qualification, not a claim that every permitted value in
that file simultaneously occupies its maximum encoded extent. It does not
qualify GSC2, physical power-loss recovery or the whole persistent Node.

Source manifests, failed attempts, actual process identities and complete logs
remain evidence. Only the parent integration workflow can register this unit
and rerun it on the final committed repository; a development result on an
isolated source snapshot does not certify every tracked Git object.
