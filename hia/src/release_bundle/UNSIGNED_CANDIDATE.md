# ReleaseBundle V0 bounded native unsigned candidate

[One emitted HIA entry](unsigned_candidate.hepta) performs the
[original V0 verifier's](../../../trillionnium/crates/trnm-release-bundle/src/lib.rs)
pure typed checks up to, but not including, signature verification. It
does not take computed hashes or validity flags from its caller. The
result is an **unsigned candidate**, not a verified release.

The private pinned ABI is `f0(input, output, scratch)`, with physically
disjoint regions. The input begins with the same exact fields and raw
rosters as the [unsigned prefix](UNSIGNED_PREFIX.md): the header, source,
artifact roster, package roster and required-package keys. Their derived
end is `P`. The full owner then reads:

| Offset from `P` | Field |
| ---: | --- |
| 0 | Build-input count (u16 little endian, 0–64) |
| 2, 34, 66, 98 | Builder identity, workflow, run identity, isolated-environment digests |
| 130, 162, 194 | Provenance's declared exact-source, artifact-set and SBOM digests |
| 226 | Declared provenance digest |
| 258 | Prior-bundle digest, all-zero for absent |
| 290 | Declared bundle digest |
| 322 | One 578-byte [build-input slot](BUILDER_PROVENANCE.md) per counted input |

Each digest is 32 raw bytes. Prior absence has the same original
canonical representation as an explicit all-zero digest. No trailing
bytes or caller-supplied offsets are allowed. All four actual/required
rosters are bounded to 64 by this private wire. That bound is not a change
to original V0 limits.

| Order | Refusal |
| ---: | --- |
| Wire | `100`, malformed frame/slot or untyped Boolean |
| 1 | `110`, invalid top-level V0 declaration |
| 2 | `101`, invalid exact source |
| 3 | `106` / `107`, invalid / duplicate artifact |
| 4 | `116` / `117`, invalid / duplicate SBOM package |
| 5 | `108`, missing required package key |
| 6 | `105`, invalid provenance identities/count or stale provenance digest |
| 7 | `126` / `127`, invalid / duplicate build input |
| 8 | `104`, inconsistent declared source/artifact/SBOM links or final bundle digest |

As in Rust, the provenance digest binds its **declared** source, artifact
and SBOM links; it is validated before the individual build inputs.
Only after provenance validation does the owner derive actual source,
artifact and SBOM digests from their raw sections. It then compares those
to the declarations. It does not overwrite the declarations before
hashing. Finally it hashes the original framed V0 bundle using the
actual digests and compares the declared bundle digest.

The private storage contract is at least 168 output and 5,360 scratch
bytes. Capacity code `102` is checked between the provenance fixed-field
predicate and its first hash (after preliminary checks). `103` is an
internal refusal. Every refusal preserves output, and those before the
first hash also preserve scratch. Scratch after hashing starts may
change but is not evidence or a returned result. Input and output/scratch
suffixes stay unchanged. The five actual digests remain in private
slots while more checks run. The entry copies them out only after the
final comparison succeeds (`0`):

- bundle, exact-source, artifact-set, SBOM and provenance digests;
- actual artifact count then actual package count (two u32 little endian).

Both pinned machine emitters exercise the same entry. The tests compile
the unchanged, locked original V0 Cargo package with its actual SHA-256
dependency and call its public typed verifier. A separate hashlib fixture
derives independent expected bytes. Original signature callback entry is
observed exactly once on positive prefix cases, and that callback always
returns an error. Cases rejected before that boundary never call it.
No case returns signature approval. Controls combine conflicting failures, validate
correctly hashed but false claims, check nonpublication even on late
mismatch, and exercise 64 rows in all sections.

The older prefix, provenance, and component entries preserve their
standalone ABIs. No signature, filesystem custody, actual builder or
checkout identity, required-list authority, retirement, or production
path is implemented by this candidate.

```sh
python3 -B -m unittest -v hia.tests.test_release_unsigned_candidate
```
