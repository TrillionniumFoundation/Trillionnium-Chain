# Bounded CTS1 post-pin metadata diagnostic

The native entry hashes and validates one immutable synthetic or other
locally obtained CTS1 metadata value within the shared 1 MiB input bound.
It is not the Rust `decode_pinned` entry. It takes no expected digest and
cannot satisfy that entry's independently supplied pin check or the
loader's separate authority checks.

Structurally it follows the original path after the pin check: parse
canonical TCV1, parse canonical TMA1, read the declared BE16 composition
file index and 32-byte profile, and require exact input consumption. Then
it compares the complete canonical TMR1 bytes in both children and checks
the nonzero declared profile and Configuration role at the original model
index. It does not choose or open any file. Validating canonical children
and consuming the exact fixed envelope makes re-encoding equal by
construction. Previous standalone owners and emitters' limits remain
unchanged.

The child checks use nonzero subspans of the same original input. A
source-pinned test mechanically reproduces their narrowly relocated
non-publishing control flow from the previous owners. The original
TCV/TMA shape, span and error checks remain in order. The resolved model
file offset table is retained in disjoint scratch at byte 13,944, above
the TMA validator's 13,944-byte footprint. No host pointer, parsed length,
trusted value, resource or result is accepted.

Only after all checks and output/scratch capacity succeeds does the
native caller stream the exact bytes through the existing SHA-512 owner
with the 35-byte domain `TRNM/Cell/TensorReleaseSnapshot/v1\0`.
It publishes 98 bytes: the exact input BE16 selection, the same 32-byte
declared profile, and the 64-byte original snapshot digest. Any refusal
preserves the whole output. Scratch is disjoint and at least 131,232
bytes. Neither the selection nor the digest verifies actual model
contents, loader compatibility, a trusted pin, a signature or authority.

The unchanged Rust oracle runs real `decode_pinned` on synthetic fixtures
using a digest computed internally from those exact fixture bytes, only
to reach the original post-pin path. The oracle also checks the actual
typed value re-encoding and commitment. Two stock emitters are checked,
including accepted exact 1 MiB, a Rust-only accepted 1 MiB+1, genuine
nonzero child offsets, last selectable index 255 and compound refusals.
No larger native CTS1 envelope or default repository/runtime integration
is supplied.

```sh
python3 -B -m unittest -v hia.tests.test_cell_release_snapshot_metadata
```

The genuine original differential uses the existing pinned
`HIA_M09_SHA2_RLIB` verification; standalone native controls still run
without that fixture library.
