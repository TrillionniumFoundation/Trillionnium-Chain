# Declared Cell bytes to immutable Linux loader descriptors

`CellResidencyV1::seal_declared_loader` adds a concrete data handoff at the
existing resident-to-loader boundary. It accepts the original independently
pinned `CellLoaderContextV1`, an additional snapshot budget, one absolute
deadline and the caller's cancellation flag. It returns a complete
`CellSealedLoaderBundleV1` only after every declared member has been copied into
an anonymous kernel file, sealed and independently read back in full.

This is a candidate M09 byte adapter. It does not change TCM1, TCD1, TMR1 or
TCV1 encoding, authentication, generation selection or signed domains.

## What the actual consumer receives

The bundle retains the admitted resident closure and exact canonical file
roster. `file(path, role)` performs an exact lookup in that roster and requires
the original role. Absolute names, case aliases, traversal, undeclared names
and wrong roles have no filesystem or network fallback. Each returned member
reports its original TCM1 identity, payload SHA-256 and payload length.

The same complete **sealed-object** readback also computes SHA-512 over
`TRNM/Cell/PayloadContent/v2\0`, the exact payload length as eight big-endian
bytes, and the complete payload bytes. `payload_sha512()` exposes that
observation for the separate full-version verifier. That verifier must compare
it with an independently authenticated v2 content pin and compare the complete
declaration returned by `closure()`. Measuring a strong hash of mutable cache
bytes and then handing off a separately reconstructed SHA-256-only snapshot
would not close that check-to-use gap. The observed digest never supplies its
own authentication or use permission.

The native `Read + Seek` implementation reads the sealed file through
positional I/O. Its cursor is local to that reader, so another reader or a
native descriptor consumer cannot move it. `AsFd` supplies a borrowed kernel
descriptor for an explicit native or cross-process adapter. Such a consumer
uses the same immutable payload; it does not reopen the original cache or a
mutable material pathname.

Each new file requires `MFD_CLOEXEC`, `MFD_ALLOW_SEALING` and
`MFD_NOEXEC_SEAL`. Its file mode is read-only, with no execute bits. The adapter
adds and reads back `F_SEAL_WRITE`, `F_SEAL_SHRINK`, `F_SEAL_GROW`,
`F_SEAL_SEAL` and `F_SEAL_EXEC`. It then checks the exact regular-file length
and computes the complete payload hash from the sealed descriptor. A source
hash measured before copying is not substituted for that readback.

Unsupported kernel flags or seals, a changed copied byte, a missing resident,
a wrong owner pin, cancellation or deadline exhaustion returns an error.
There is no temporary-file, unsigned-file or mutable-path fallback. A failure
in a later member closes every unpublished descriptor and returns no partial
bundle. The resident pool's usage and local selection remain unchanged.

The implementation uses safe `rustix` interfaces and retains the crate's
`forbid(unsafe_code)` policy. Linux selects the module explicitly; other
platforms do not acquire an emulated sealing API.

## Memory and time accounting

`CellSealedLoaderLimitsV1` bounds the complete additional copied payload and
file count before the first descriptor is created. It counts every declared
file in full, including bytes that the original resident pool deduplicated.
The existing resident bytes stay charged while the snapshot exists; the copy
is additional memory, not a zero-copy or NVMe placement claim.

This is a per-bundle logical payload bound. It excludes metadata, kernel
overhead, downstream mappings, tensor deserialization, allocator overhead and
GPU allocations. The ordinary execution owner must reserve those resources
and account for concurrent bundles. No VRAM, device-memory or whole-process
RSS reservation is created here.

The original absolute deadline and cancellation flag are checked throughout
copying, sealing and full readback, including after the last member. Neither a
new file nor a readback receives a fresh time allowance. Individual operating
system calls remain cooperative rather than hard-real-time preemptible.
Preparation success does not extend the original owner's startup or inference
window.

## Lifetimes and authority

The complete bundle borrows its original resident. Safe Rust cannot evict or
switch that manager while a bundle or returned file view remains borrowed.
There is no owned payload `Arc` in the public handoff.

An operating system descriptor can be explicitly duplicated or mapped by a
downstream owner. Those references can outlive the Rust borrow and preserve
the sealed object. Dropping the bundle therefore is not evidence that all
memory was reclaimed, and it grants no refund. Cross-process ownership and
reclamation remain the real runtime's responsibility. Descriptors retain
CLOEXEC until that owner explicitly arranges the chosen handoff.

The adapter confines its own file lookup to the declaration. It does not
sandbox arbitrary loader code or stop that code from independently opening an
undeclared file, importing a library, allocating a device buffer or making a
network request. The ordinary Hepta owner must integrate these descriptors at
its existing material-loading entry, preserve its protected executable and
runtime-source admission, and enforce CURRENT, withdrawal, generation,
resources and FinalUse at actual use. A verified SHA-256 snapshot alone does
not increase TCM1's hash-security level or establish complete PQ qualification.

## Native controls and remaining acceptance

The new native controls exercise actual kernel seals and rejection of writes,
truncation, growth and adding executable permission. A native child receives
the real descriptor through standard input and returns its actual bytes. The
existing native strict safetensors parser consumes the same `Read + Seek`
interface against separately declared F32 tensor shapes and whole-file hashes.
These fixtures are bounded synthetic tensor containers, not trained-model
inference or Hepta Ready receipts.

Negative controls cover undeclared names and roles, independent reader
cursors, replacement of the original cache pathname, a changed copied byte
before sealing, limits and owner-pin mismatch, preexisting cancellation and
expiry, and a cancellation or deadline reached after earlier files have
already been sealed. Failed publication retains no partial loader bundle.

These tests establish the native immutable-byte handoff. They do not close
ordinary Hepta model load/query/unload, complete runtime namespace confinement,
NVMe/VRAM admission, independent WAN custody or a production activation gate.
