# Offline selected held cache-chunk read

This bounded pure observation joins the original cache payload cursor
plan with the very same immutable bytes supplied to the call. One stock
read loan, at most 1 MiB total, is encoded as LE64 logical position,
LE64 requested byte count, LE32 TCM1 size, canonical TCM1 bytes, then
one held chunk. There is no caller-supplied row index, chunk offset,
hash result, verification flag, or ownership handle.

The published TCM1 parser validates the complete declaration first.
On a nonempty request below EOF, the published cursor's exact row
selection uses the first actual declared chunk width. The native owner
hashes the supplied bytes with ordinary SHA-256 and compares the
result to the digest in that selected TCM1 row before requiring its
exact byte count. This follows the original cache lookup's content
digest check and the original reader's subsequent length equality,
not a different length-first store-ingestion helper. Empty/missing
held input or mismatch returns 247; a matching digest of the wrong
declared length returns 248.

On success the output is LE64 next position, LE64 copied count and
the exact one-chunk slice, truncated at the original chunk boundary or
requested count. At EOF or for a zero request, the held bytes are not
inspected, no hash scratch is needed, and success contains the old
position with zero bytes. No refusal modifies output; success leaves
its unused suffix intact. Malformed envelopes return 100, TCM1
diagnostics remain unchanged, and insufficient work/output returns
102. A nonempty read uses 1,232 bytes of hash scratch. The complete
loan limit includes framing and declaration; it does not qualify
the original 4 MiB maximum cache chunk.

The offline comparator uses the actual locked original TCM1 decoder
and SHA-256 dependency, exact frozen store digest/equality statements,
and original reader selection, extent, byte-copy and cursor-update
statements. The isolated test observes only bytes already supplied,
not a read of a store or a fetched result. It intentionally omits
deadlines, SQL, cache lifetimes, corruption cleanup, observation
authority and production ownership. This is neither cache access nor
a substitute for original reader I/O semantics.

```sh
python3 -B -m unittest -v hia.tests.test_da_cell_cache_payload_held_read
```
