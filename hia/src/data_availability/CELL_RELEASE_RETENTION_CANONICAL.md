# Immutable TCA2 archive declaration and commitment

This bounded private kernel compares the same typed declarations as
the public original `CellReleaseRetentionContractV2::{validate,commitment}`
and emits the original SHA-256 on acceptance. This is not qualification
of the original private decoder's malformed-input diagnostic ordering
or any physical archive owner, storage, retention or funding action.

One immutable loan holds `NTA20001`, the opaque declared store ID (32
bytes), a big-endian capacity (u64), maximum obligations (u32), maximum
releases (u32), eight reserved zero bytes, and then the exact canonical
TCA2 wire. The combined extent is at most 1 MiB. The kernel requires
18,080 scratch bytes: the prior validators use their existing offsets;
the end contains at most 256 eight-byte previous object offsets. The
first 32 output bytes receive the digest on success; other bytes and the
input remain unchanged. On refusal the complete output is unchanged.

Within the bounded typed profile the order is original retention/archive
config, exact canonical declared TMR1, optional valid TMA1 and exact
model-root byte equality, outer identity/replica/half-open lease terms,
object count, per-object terms, exact derived TCM1 membership against
the closure's descriptor, canonical manifest ID order, original
per-set object uniqueness and lease coverage, then raw declared capacity
sum. TCA2 uses the raw payload sum, not TCA3's page-aligned sum, and it
does not import TCA3's different operation/funding set predicates. No
caller-supplied manifest IDs, predecoding verdict or prehash replace
these checks. The 1 MiB envelope and original member extents make
oversized original wire and u64 size overflow unreachable. When all
checks succeed, hashing uses the original domain including its NUL,
the declared store ID and all borrowed canonical TCA2 bytes.

The locked Cargo test calls public original typed validation and
commitment for owned synthetic declarations. Positive fixture framing
is independently checked against the digest from the original internal
encoder; every accepted fixture is byte/digest-compared with both pinned
stock native emitters. Real Rust cases include 256 members, optional
TMA1, raw-versus-aligned capacity, object ordering and payload mismatch.
Malformed wrapper and wire controls are separately native-only because
the original raw decoder is private.

```sh
python3 -B -m unittest -v hia.tests.test_da_cell_release_retention_canonical
```
