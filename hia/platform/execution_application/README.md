# Native default M06 application owner

This component executes the original `pon_executor::prepare` and
`apply_authenticated_application` boundary under the internally constructed
default `Config::installed()` / `Settings::development(None)` configuration.
The production Linux executable contains fourteen actual HIA images. It owns
the prepared transaction, State/View/Patch objects, application continuations,
typed values, temporary allocations and account callback state in private
anonymous mappings. No Python or Rust algorithm runs inside that executable.

## Source and authority boundary

The application images implement every command reachable under this default
configuration: tags 1 through 12. Preparation decodes the complete PNX1 wire,
checks the original configuration and expiry rules, computes the original
signing digest and transaction identity, and runs the existing native strict
Ed25519 verifier. The application receives the successful private preparation
arena directly. External input cannot import a Config, Prepared, signature
verdict, Patch, expected root or `AdmissionPersistence`.

The original production boundary is
`trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs`. The application first
borrows a real State and creates a real View. It preserves the original order
of account access, nonce arithmetic, base and byte fees, fee-limit checking,
fee debit, command execution, nonce update, receipt and consuming Patch
creation. The quota-use fee exception and its strict lowercase public-key
decoding follow the original methods. A successful call returns a private
Patch handle; it does not mutate the borrowed State. Failed, panicking and
cancelled calls retire the temporary View and all owned Values.

The reused `execution_state` owner preserves typed JSON Values, including
unknown object fields, UTF-8, integer and floating-point distinctions, and
the original equality of positive and negative floating zero. Prefix scans
capture the complete ordered observation. Point reads and writes remain
independent conflict checks. `Patch.current` checks those real observations.
`Patch.apply` consumes the Patch and follows the original method without an
implicit `current` check. Test control can apply or drop an observed Patch;
this process-local operation is not block admission or persistent COMMIT.

Dynamic Values and prefix snapshots grow with actual native allocations.
No new 4096-byte Value limit, one-megabyte State limit or truncated prefix
scan is introduced. The original root routine enforces its own limits when
root calculation is requested. The original PNX1 transaction maximum remains
2048 bytes. A larger public input is consumed in full before preparation
reports the original encoding failure. Linux representability and actual
allocation failure are separate process failures.

## Native composition

| Images | Responsibility |
| --- | --- |
| `state`, `root` | Existing native State/View/Patch owner and full root |
| `settings`, `pnx`, `sha`, `ed` | Native default context, wire decoder, SHA-256 and strict Ed25519 |
| `prepare_bridge` | Private continuation into the unchanged preparation kernel |
| `core` | View ownership, account access, fees, nonce, receipt, value helpers and cleanup |
| `task`, `model`, `release`, `quota`, `relation`, `claim` | Complete default application commands and their scans, hashes and checks |

`linux_emitter.hepta` is compiled by the pinned native HIA compiler. It emits
the Linux prefix that joins the fourteen compiled images. Its literal syscall
and ABI bytes are an explicit trusted adapter boundary. Development assembly
and authoring programs are not build or runtime dependencies. The compiler
pin and backend limits are unchanged; each entry has exactly three buffer
capabilities carried by the six supported SysV argument registers.

`source_graph.py` selects declared, original HIA function bodies recursively.
It captures the complete State and Prepare source closures, all application
owned files, the canonical include graph, four configuration files, the
compiler qualification inputs and pinned build inputs. It also captures the
original Cargo path/include dependency graph, including its two external
test fixtures. Missing, extra, changed, symbolic, cyclic or undeclared input
dependencies are refused. Fixture Python is compiled from the bound source
bytes, not imported from a stale bytecode cache.

## Public process protocol

The executable accepts three distinct blocking pipes: read-only stdin and
write-only stdout/stderr. It checks the actual descriptor type, access flags
and device/inode identity before any output. Failed descriptor admission exits
silently with code 64. Ordinary terminal or regular-file redirection is not
part of this limited process ABI.

Each command and ordinary response has a little-endian u64 length prefix.
Startup returns `APREADY1`, the native context length and actual SDO1 bytes.
State commands use the unchanged `SVP00001` protocol. Application commands
contain `APPLY001`, the private base-State handle, height, wire length,
account-callback flag and complete raw PNX1 transaction. The native process
performs preparation on each application input; an `MPVALUE` observation is
never accepted as authority.

With account callbacks enabled, the owner emits `APCALL01`, its strictly
increasing callback ordinal and exact account bytes. The caller replies with
`APGO0001`, the same ordinal and action 0 to continue or 1 to cancel. Cancellation
produces the original account-access error and no Patch. Malformed, stale,
truncated or invalid-action acknowledgements fail the process. A future
worker scheduler must release the heap lock before waiting for this callback.

`APRESULT` carries the outcome, original error code/text, private Patch handle,
fee, account-access count, receipt, private preparation generation, height and
command tag. Outcomes distinguish ordinary error, caught original Value panic,
callback cancellation and a private invariant failure. Preparation errors use
the existing `MPRESULT` observation and never expose a ready value. Process
failures use `SVPFAIL1`: 64 for framing/admission, 72 for allocation or mapping,
73 for an internal invariant, and 74 for I/O. SIGPIPE is ignored so EPIPE is an
observed I/O failure. Known exits erase and unmap private memory; SIGKILL is
recorded as abrupt process death and never claimed to perform cleanup.

The complete field offsets, phase numbers, literal ranges, image dispatch and
private coroutine slots are in `abi.json`. They are internal calling contracts,
not additional public import endpoints. The first application call borrows
the real Prepared span of at least 50184 bytes; later calls borrow the actual
native completion buffer. All persistent references are offsets or private
owner handles, so a real `mremap` cannot leave a borrowed host pointer behind.

## Qualification commands

Use the pinned HIA toolchain and compiler described by the repository lock and
qualification binding. Run Python with `-B` and without `PYTHONOPTIMIZE`.
Every output directory must be new and outside the repository.

```sh
python3 -B -m hia.platform.execution_application.test_integrity --output /new/source-gates
python3 -B -m hia.platform.execution_application.qualify --output /new/native
python3 -B -m hia.platform.execution_application.physical --output /new/physical --require-trace
python3 -B -m hia.platform.execution_application.test_integrity --output /new/bundle-gates --bundle /new/native/bundle
python3 -B -m hia.platform.execution_application.rust_oracle --repository /exact/repository --bundle /new/native/bundle --output /new/original --target-dir /isolated/cargo-target
```

The canonical corpus has 328 histories and 335 transactions. It retains all
323 original development inputs and adds five strict public-key/error-order
cases after an actual original differential found one uppercase-key acceptance
bug. The old failed observation remains historical evidence. The corpus covers
all twelve default tags, complete typed values, prefix scans, current checks,
consuming apply/drop, error precedence, cancellation, sequential state, allocation
trees, quota authorization and root outcomes.

The public evidence gate verifies the full compiled source closure, actual
native image ordering and ELF bytes, every compiler/emitter stage, source-derived
corpus bytes, bounded XZ stream, complete native stdin/stdout/stderr and every
observer frame. It replays only the observer protocol against those actual
pipes. It does not implement State or application algorithms.

The original oracle copies the complete unchanged Rust source graph into a
fresh isolated tree and appends one private `cfg(test)` child declaration. It
uses real `prepare`, application, Value, State, View, Patch and root methods.
It compiles the actual locked Cargo graph, binds the selected absolute compiler
and Cargo executables, verifies the single serde_json library artifact and its
exact crate archive/source bytes, preserves an independent test binary, executes
eight original retained tests and all 328 histories, and checks source, tools,
artifacts and binary again on every exit. Missing Rust tools are `NOT_RUN`, not
a passing oracle. Raw caught panic output remains preserved.

Physical qualification is separate from semantic equivalence. Its actual
descriptor, private ABI, allocation, EPIPE, signal and trace observations are
source-bound and retain their raw input/output and private fixture journals.
Private counter fixtures and injected kernel errno are identified explicitly;
they are not production inputs or claims of physical memory exhaustion.

## Remaining owner boundaries

This component does not complete the batch executor, worker lifetime and join
semantics, mandatory transitions, mature rewards, funds conservation, paid CPU
accounting, nondefault configuration branches, PQ profiles, block authority,
expected-root admission, reorganization or durable Node COMMIT. Those owners
must call the actual private Prepared and State continuations in the same
native process and preserve the original failure ordering. Component histories
or source checks alone do not close those boundaries or authorize retirement
of the old runtime.
