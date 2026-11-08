# M15 static execution closure V2

Status: **RESEARCH / HOLD / NO-GO**. This is a narrowing of the existing Chain
M15 native consumer and a repair of the actual material reader. It does not
qualify a general model loader, an independently controlled deployment, or
production activation.

## Actual bytes consumed

`operator_continuous_policy::HeldCatalog` and
`operator_mining_policy::HeldCatalog` retain the SHA-256 already authenticated
for each material, alongside its open descriptor and filesystem identity.
`read_role` reads by explicit offset, hashes the bytes placed in the returned
buffer, and refuses any digest or length mismatch before returning that buffer.
The identity checks before and after reading remain mandatory. Revalidation
also binds each retained digest to the current material row.

The previous reader duplicated a file handle and sought the duplicate. Rust
documents that duplicated handles share the same underlying file cursor;
another holder can redirect subsequent reads without changing inode metadata.
The retained regression changes only that shared cursor between two 64 KiB
chunks. The old reader could return the first chunk twice while its length and
metadata checks still passed. This is a component-level counterexample using
the real reader, not a forged production authorization or a claim that the
128 KiB fixture is an accepted native model shape.

The repaired reader uses `FileExt::read_at`, whose offset is independent of the
shared cursor. Hashing occurs inside the existing bounded, progress-checked
read loop. It introduces no second file scan or unmetered resource discovery.
Cancellation, the role's caller-supplied byte limit, exact length, and changed
path/descriptor metadata still refuse admission. A successful returned buffer
is the buffer verified at this boundary; a receipt describing other bytes is
not substituted for it.

References: Rust's [`File::try_clone`](https://doc.rust-lang.org/std/fs/struct.File.html#method.try_clone)
and Unix [`FileExt::read_at`](https://doc.rust-lang.org/std/os/unix/fs/trait.FileExt.html#tymethod.read_at).

## Explicit static process profile

New executions require `trnm-operator-m15-sealed-native-elf-v2` in the signed
complete execution contract. V1 retains its original interpretation for
historical record replay, but cannot authorize a new execution or a current
use through the upgraded owner. The existing protected namespace, monotonic
history, claims and unknown attempts are not reset. A transition requires a
new current configuration through the original release authority. Changing the
profile label alone cannot reuse the old complete signed environment.

The existing sealed memfd, actual `/proc/self/exe` identity, complete argv,
working-directory identity, current release authority, one-shot claim and
exact material-catalog checks continue to apply. The static ELF parser still
refuses `PT_INTERP`, external dependencies, dynamic search paths, filters and
audit objects. V2 additionally requires one explicit non-executable
`PT_GNU_STACK`, refuses text relocations, and requires executable load segments
to be entirely file-backed. Ambiguous repeated stack declarations are refused
even though Linux selects the last such declaration. Ordinary non-executable
zero-filled data remains allowed.

The exact child environment is:

| Name | Exact value |
| --- | --- |
| `LANG` | `C` |
| `LC_ALL` | `C` |
| `OPENSSL_CONF` | empty string |
| `OPENSSL_ENGINES` | `/proc/self/exe` |
| `OPENSSL_MODULES` | `/proc/self/exe` |
| `TZ` | `UTC` |

The consumer checks this fixed environment before opening release authority
and rechecks it at use. Administrator commands must supply the three explicit
OpenSSL controls before any M15 authority/provider operation. They may retain
other administrator environment entries; the sealed child receives exactly
the six signed entries. No code mutates the process-wide environment after
threads have started.

The default PQ implementation uses RustCrypto ML-DSA. The OpenSSL restriction
also protects supported builds that include optional native OpenSSL code:
an absent `OPENSSL_CONF` permits the installed default configuration, while
the explicit empty string disables it. The engine/module locations name a
regular executable file, which cannot be a search directory. Secure execution
can ignore these controls, so the profile refuses `AT_SECURE`, mismatched
real/effective user or group IDs, and missing or malformed auxiliary-vector
evidence. Environment text alone is not treated as proof of that kernel mode.

References: Linux [ELF program-header behavior](https://origin.kernel.org/doc/html/v6.18/userspace-api/ELF.html)
and OpenSSL [configuration semantics](https://docs.openssl.org/3.5/man5/config/).

## Capability boundary and remaining qualification

This profile supports the existing static Chain Node, its exact signed startup
configuration and its bounded native `model`, `input`, `spec` and PQ bootstrap
materials. It does not implement arbitrary Python interpreters, shared-library
dependency resolution, external tokenizer or router plugins, remote weights,
JIT compilation, or a complete Hepta model runtime. Those require their own
explicit authenticated dependency closure and actual-use integration; they
cannot inherit acceptance from this change.

This is not a general operating-system sandbox. A signed malicious executable
could issue arbitrary syscalls, use absolute-path dynamic loading or modify
its own memory. The release authority remains responsible for approving the
executable and its source/build provenance. No `/proc/maps` snapshot is used
to claim that future loads are impossible. The OS, kernel and independently
provisioned protected trust root remain in the existing trusted boundary.

Parser and reader regressions do not establish a successful isolated native
deployment, original-8193 resource qualification, public WAN admission,
whole-state rollback resistance, provider reconciliation, or independent
administrative control. The [retained run record](../../evidence/loader-closure-20261108/README.md)
separates original failures, corrected checks and unexecuted qualification.
