# Fresh native Host checkpoint owner

This new HIA candidate owns actual Linux file syscalls for acquisition and each
fresh fixed-parent check. It is a source reconstruction after loss of the
unpublished earlier candidate; it inherits no earlier 169-case qualification.

Production path/UID/limit policy is fixed. Acquisition walks `/`, `sys`, `fs`,
`cgroup`, and `trnmponpublic.slice` with O_PATH and O_NOFOLLOW before the original
controller/type checks. Each subsequent check freshly reads complete boot and
calling-thread membership text, opens the actual parent, reads all five bounded
regular limit files through EOF, parses in original order, performs the final
path identity fence, and closes descriptors. No file content, descriptor or
successful decision is reused between checks. Only acquired immutable identity
and private buffer capacity survive.

The checked-in `.hepta` files are complete build inputs. Python orchestrates the
pinned native HIA compiler and HIA ELF emitter and records physical observations;
it does not own runtime I/O or emit instruction bytes. The emitter admits a
small read-only syscall profile and bounds command/state-relative pointers.
Private state grows only through a checked mremap of the adapter-owned mapping.

The fixture entry changes only the explicit fixture flag. All production helper
bytes remain identical. Fixtures use actual native reads of private files and
their own UID; they confer no production Host authority. No parser output or
caller-supplied metadata can replace actual syscalls.

Build and qualify from the repository root with the explicitly pinned toolchain
environment used by other platform components:

```sh
python -B -m hia.platform.host_checkpoint.build --output /tmp/hia-host-build
python -B -m hia.platform.host_checkpoint.qualify --output /tmp/hia-host-qualified --require-trace
python -B -m hia.platform.host_checkpoint.rust_oracle --output /tmp/hia-host-original
```

`--require-trace` fails closed if independent syscall tracing cannot execute or
validate. Core and ELF shape checks alone do not prove machine-code semantics.
The complete original `host_kernel_parent.rs`, its relative tests, `error.rs`,
the original comparison adapters and production CI controller are in every
source manifest; missing, modified or symlinked inputs cannot inherit a build
receipt. Production qualification also checks the complete exact committed
repository before and after execution.

Qualification executes actual private files, descriptor cleanup, ancestor
substitution, fresh-context and limit races, EOF/error order, real interrupted
FIFO opens and reads, positive short reads, state growth and allocation failure,
and malformed native adapter commands. The independent trace must observe the
complete canonical walk, original initial metadata order, fresh stream reads
through EOF, five regular-file checks, final inode fence, and closed descriptors.
Synthetic trace examples test the evidence parser only. If ptrace is denied, the
report records UNKNOWN and `--require-trace` exits unsuccessfully.

The original comparison executes 145 matching real-file cases through the
actual original private primitives and test-only fixture sequences. The entire
production Rust file remains unchanged, including in the isolated Cargo copy;
only its already test-only relative include gains a child adapter. The original
Host tests run as well, with nine essential tests required to execute. The
default comparison runs native and Cargo stages and fails if Rust is unavailable.
An explicit `--native-only` result means `NATIVE_PASS_ORIGINAL_NOT_RUN`. Private
fixture comparison does not certify the original production fixed-path owner.

The mandatory hosted job separately runs `qualify_production.py` against the
sealed production image. It requires an exact-source GitHub-hosted job, refuses
a preexisting parent or runtime unit, atomically installs only the reviewed unit
and records its root-owned lease. It runs as the original unprivileged UID/GID
inside `/trnmponpublic.slice`, with all original parent limits unchanged. Native
receipts and an independent syscall trace must agree on 22 fresh checks; the
actual calling TID, cgroup membership and running executable are checked. The
controller cannot supply a success verdict to the image. It preserves failure
output even when the child has already exited, records primary and cleanup
failures separately, and stops only its uniquely owned service. Job-created
parent resources remain for ephemeral-runner teardown. It refuses local or
self-hosted provisioning; these checks grant no production-positive PASS until
the actual hosted run succeeds.
Failures also emit bounded, JSON-escaped tails of the actual controller and child
logs. Artifact collection selects explicit reports, builds, syscall traces and
original-stage logs; intentionally unreadable physical fixture directories are
not traversed by the uploader. No diagnostic observation substitutes for a native
success receipt or a successful independent syscall trace.

The first hosted jobs failed and their artifact upload was blocked by an
intentionally unreadable fixture. After explicit artifact selection was added,
the `8690b8b` push job retained its actual production trace: the native process
exited zero after 22 successful fresh checks, but the trace verifier failed.
Its quoted-string mapper incorrectly paired quotes across syscall lines when a
read payload contained escapes. Mapping now recognizes complete escaped strings
only in the path argument of `openat` and `newfstatat`; read/receipt payloads
remain byte-exact. The unchanged 888-call trace is retained in the
[diagnostic record](../../qualification/host-production-trace-parser-development.json)
and independently replays through all 22 checks. The failed job stays FAIL;
this offline regression is not a new production execution. Eleven production
controller tests and four fixture/evidence tests pass. New committed-source
production execution remains mandatory.

The standalone image is not yet the HIA full-node Host. It must execute in the
actual worker thread at every original checkpoint; a sidecar cannot attest
another thread's membership or CPU clock. Resource sampling, original service
budgets, actual production fixed-parent positives and full-node integration are
separate gates. Process-wide signal disposition also requires ownership review
before embedding. See `abi.json` for the finite protocol and error meanings.
