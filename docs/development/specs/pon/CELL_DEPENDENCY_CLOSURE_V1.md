# Cell dependency closure v1 (TCD1)

Status: candidate library/native-fetch/CLI boundary. This is a **declared byte closure**
qualification. It does not establish ordinary Hepta installation, safe tensor
loading, learning improvement, CURRENT selection, storage availability over time,
or FinalUse authorization. There is no new release owner or registry.

## Integration and ownership

The existing release/loader owner supplies an independently trusted closure id,
five-part `CellContextV1`, selected generation, loader profile digest, required data
roles, and payload/chunk budgets through `CellLoaderContextV1`. Peer discovery
cannot choose these values. The profile identifies the existing loader's expected
format, shape and ABI policy; equality of its digest does not execute that policy.

`CellReleaseClosureV1` extends an embedded, unchanged canonical TCR1 manifest with
file mappings and explicit dependencies. Each file points to one unchanged TCM1
content identity and repeats its payload SHA-256 and length. This wrapper changes
neither TCM1/TCR1 identities nor TCL4 transport. Existing callers of
`fetch_release_to_file` keep their original TCR1 completion marker.

`fetch_closure_to_file` verifies the owner context, then uses the same native
release-fetch implementation. All TCM1 identities, contexts, payload hashes and
lengths must match before **any member payload request**. Aggregate TCM1 payload
and chunk totals must satisfy both caller and loader budgets. One original
connection/response/deadline reservation covers every manifest, chunk and retry.
Complete cached bytes are rechecked with the existing release verifier. Only
then is the canonical TCD1 marker published through the existing create-only
temporary-file/fsync/no-replace hard-link path.

A failure before publication leaves no completion marker; verified disposable
cache data may remain for resumption. A failure after the hard-link boundary can
coexist with a complete marker, with the same reconciliation rules as TCR1.
Markers do not lease cache entries. The consumer must reverify bytes immediately
before loading and obtain its ordinary owner admission separately.

## Existing CLI entry point

The existing `trnm-cell fetch-closure` command consumes `--closure-file` and the
independent `--closure` content id, `--loader-generation`, `--loader-profile`,
`--required-roles`, and all six context arguments used by `pack`. It uses the
existing cache caps and release byte/chunk/response/connection/deadline limits.
The complete TCD1 marker is the command's `--output`; data files are still handled
by the existing cache and safe loader. Context and profile values are mandatory
caller inputs; the CLI does not copy its expectations from peer metadata.

Authentication selection is explicit: `--authentication-profile content-cache-v1`
or the existing `cell-pq-v2` with its original independent key/currentness arguments.
CPR2 authenticates the embedded **TCR1 only**. It does not sign TCD1 path, graph,
generation or profile metadata. The original owner must independently pin the
entire TCD1 id, regardless of the selected transport release profile. Unknown
profiles and failed PQ checks never fall back to unsigned admission. Pin and PQ
admission complete before a writable cache is opened or a peer is dialed.

The CLI currently requires Unix descriptor I/O, opens the input with
`O_NOFOLLOW | O_NONBLOCK`, checks a regular-file size before bounded reading, and
rejects a changed length or content identity. This does not claim to hold the
caller's entire parent directory namespace against racing local substitutions.
The input and output parent directories remain caller-controlled.

## Canonical file and graph rules

Files appear in strictly increasing path order. Roots and each dependency list
are strictly increasing unique u16 indices into that order. Every file must be
reachable from at least one root. Dependencies form an acyclic graph whose
longest root-to-leaf path contains at most 16 files; shared descendants are
allowed. At most 256 files are permitted. A TCM1 identity appears exactly once,
and the set of identities equals the embedded TCR1 membership exactly.

Paths contain only ASCII letters, digits, `.`, `_`, `-` and `/`. Their exact case
is retained, including the existing Hepta profile's mandatory `base/README.md`.
Case-folded names must also be unique, and file/directory prefix checks use
case-folded names, so this does not introduce aliases on case-insensitive filesystems.
They contain at most 255 bytes and eight components; each component has one to 64
bytes, starts and ends without `.`, and is not a Windows device name (`con`,
`prn`, `aux`, `nul`, `com1`–`com9`, `lpt1`–`lpt9`, including extensions).
Empty components, absolute paths, `.`/`..`, backslashes, colons,
Unicode and file/directory prefix collisions are rejected. These restrictions
reduce cross-platform path aliases; this implementation does **not** create the
file tree. Any future materializer must additionally prevent symlink traversal
and racing filesystem substitutions using the existing safe loader's filesystem
boundary.

Roles are data-only tags: base (1), tokenizer (2), preprocessor (3), adapter (4),
router (5), configuration (6). Unknown values are invalid. Roles neither request
code execution nor provide an alternate loader. A loader's required roles are
nonempty, unique, and must all occur in the closure. Optional roles are allowed
only as ordinary data members under the same owner-pinned closure id.

The owner must supply a semantically complete dependency graph. The validator
cannot infer a missing model dependency, identify an omitted tensor, or prove
that a tokenizer is compatible merely from a declared graph. Those checks remain
with the existing loader and its model-specific expected profile.

## Wire format and content address

All integers use unsigned big-endian encoding. There is no padding or trailing
data. The complete object is at most 1,048,576 bytes.

| Field | Encoding |
| --- | --- |
| Version | Four bytes `TCD1` |
| Selected generation | u64, nonzero |
| Loader profile | 32 bytes, nonzero |
| Embedded release length | u32 |
| Embedded release | Exact canonical TCR1 bytes |
| Root count and roots | u16 count, then u16 indices |
| File count | u16, 1–256 |
| Each file path | u16 byte length, then portable ASCII bytes |
| Each file role | u8 (1–6) |
| Each file manifest id | 32 bytes, nonzero |
| Each file payload SHA-256 | 32 bytes, nonzero |
| Each file payload length | u64, 1–64 GiB (existing TCM1 limit) |
| Each file dependencies | u16 count, then u16 indices |

The id is `SHA256(b"trnm.cell-dependency-closure.v1\0" || canonical_TCD1)`.
Bounds are checked before decoder allocations. This is a new content-address
domain, **not a signature scheme**. Authentication of the expected id belongs to
the existing release owner and its current cryptographic admission path.

## Evidence and limits

The Python reference codec uses independent topological elimination to check
acyclicity and longest paths; Rust uses bounded depth-first traversal with
memoized heights. Both consume the fixed vector at
`formal/pon-nakamoto-v1/vectors/cell-dependency-closure-v1.json`. Its three payloads
are tiny public synthetic byte strings, explicitly not model weights.

Rust tests exercise the actual cache, the supported binary with real argv, and a
loopback TCL4 server: successful complete
publication, metadata failure on the last manifest before any payload fetch,
owner chunk-budget failure before payload fetch, and partial transfer followed
by bounded cache resumption. Codec/graph tests cover truncation, overlong counts,
wrong membership, cycles, missing/unreachable dependencies, path aliases, owner
context mismatch, and longest paths through shared descendants. Existing TCR1
publication race, deadline, lost-acknowledgement and no-replace tests remain the
regression gate for the shared publication code.

No ordinary Hepta CLI caller is added here. The downstream integration must map
an existing owner-approved complete release to this byte plan, validate loaded
tensor/tokenizer/router semantics, execute the ordinary installation/readback
path, and prove three real feedback rounds. Native Hepta consumption and those
model rounds remain PN3 integration/qualification gates; this byte-closure slice
does not move them to another phase or declare PN3 complete.
