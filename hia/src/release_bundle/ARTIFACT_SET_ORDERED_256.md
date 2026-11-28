# Original V0 ordered artifact-set digest, 256-slot diagnostic

The private entry computes exactly the original
`ReleaseBundleV0::artifact_set_digest()` value over an immutable packet.
The packet starts with a little-endian u16 count, then exactly that many
original 877-byte artifact slots. This entry has no mode byte, no
membership check or other authority. It accepts zero through 256 rows,
retains duplicates, and sorts by original complete typed order (including
numeric u64 size rather than on-wire byte order). It hashes canonical
original members behind the raw original artifact-set domain.

The common ordered-release driver is also used by the separate 256-slot
SBOM digest. Private entrypoints fix the profile themselves; no mode or
comparison callback is supplied by a caller. The largest artifact input
is 224,514 bytes. Scratch is 16,384 disjoint bytes: aggregate and hash
work end at 11,020, then two 2,048-byte index banks begin at 12,288.
There are at most eight full merge passes, 2,048 merge copies, and no
more full member comparisons. Output publishes a 32-byte digest only
after the complete fold (0); 100 is wire refusal, 102 is private capacity,
and 103 is private hash failure.

Locked Cargo qualifies the real original public value from inert typed
fixtures, including 256 maximum-width rows, stable duplicate
multiplicity, permutations and numerical u64 extremes. Both native
backends run the actual component. The previous 64-row standalone ABI
and original unsigned-candidate limits are intentionally unchanged.
No release validity, provenance, signatures, production routing or
deployment is implemented.
