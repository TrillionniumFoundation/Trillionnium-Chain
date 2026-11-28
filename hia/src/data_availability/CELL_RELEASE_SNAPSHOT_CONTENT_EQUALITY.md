# Offline CTS1 supplied content equality

The caller loans a single immutable envelope: 64 expected digest bytes
followed by the raw CTS1 metadata. The original shared input loan remains
limited to 1,048,576 bytes total, so the wire portion is limited to
1,048,512 bytes. The original Rust CTS1 wire limit is greater. This entry
does not widen the ABI, run the original as a fallback or claim validation
above the shared envelope limit.

Within that bound, before parsing any wire shape, the entry checks the
original minimum wire length (46), then refuses an all-zero expected
digest, then computes SHA-512 of the original
`TRNM/Cell/TensorReleaseSnapshot/v1\0` domain and the exact wire subspan
excluding the expected prefix. A mismatch has the same status as zero
(208). Only equality reaches the previous canonical CTS1 TCV1/TMA1 and
metadata checks, including canonical TMR1 equality and Configuration
selection. The pinned previous layout graph is mechanically relocated to
offset 64 without changing its public source or machine artifact.

The caller supplies disjoint buffers and 131,232 bytes of scratch. A
nonzero expected digest on short scratch is a separate native capacity
refusal (102), not a Rust format error. Output capacity is checked after
all wire conditions. Success atomically writes 98 bytes: the declared
BE16 index, the 32-byte declared profile, and the same computed digest.
The digest is computed once and retained outside the nested validator's
scratch footprint. On rejection, the output is unchanged; zero or
length refusal also leaves scratch unchanged.

The expected digest may be supplied by anyone. Equality does not
establish a trusted snapshot, independent owner expectation, signature,
loader compatibility, actual file/model contents or an authorization
decision. This entry is not wired into production.

The locked original differential passes the **exact same supplied**
zero, wrong or matching expected bytes to genuine Rust `decode_pinned`,
without calculating or replacing that argument in the Rust observer.
The fixture exercises original length/digest/layout order, compound
refusals and the common total cap. It is entirely offline.

```sh
python3 -B -m unittest -v hia.tests.test_cell_release_snapshot_content_equality
```

The genuine original observer uses the same verified
`HIA_M09_SHA2_RLIB` graph as the post-pin metadata diagnostic.
