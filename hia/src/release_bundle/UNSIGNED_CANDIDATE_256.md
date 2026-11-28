# Separate V0 unsigned candidate, indexed 256-slot profile

A fixed private bounded native entry over the exact immutable
[V0 unsigned layout](UNSIGNED_CANDIDATE.md) and original deterministic
checks. Each of its four rosters is capped at 256; the maximum packet
is 917,357 bytes, beneath the common 1 MiB borrowed ABI.
It uses the existing offset-bound sorted digest folds without changing
the old 64- or 128-slot ABIs or any prior member/digest implementation.
On success it emits the same 168-byte unsigned candidate data, not a
verification receipt. There is no signature operation or authority.

Rather than a quadratic walk over previous names, each membership
stage scans the original-order **valid prefix** of the roster up to its
first invalid row, sorts just those indices in a private two-bank
buffer, and scans adjacent sorted typed keys for duplication. The
original order comparator begins with the same respective uniqueness
key (artifact name, SBOM name and version, or build name and source).
Thus any duplicate found entirely within the valid prefix was reached
before the first invalid row; an invalid row cannot be mistaken for a
duplicate of an earlier valid one. Nothing follows a roster refusal.
SBOM required keys use bounded binary search over the exact remaining
fully validated sorted SBOM index bank; equal names with differing
versions are independent keys.

Every sort has at most eight passes of 256 merge copies and at most
that many complete typed comparisons. The membership loop adds at most
255 adjacent-key comparisons and linear validation. Each required lookup
uses at most nine comparisons, at most 2,304 in all. These are worst-case
counts, not a predicted production latency guarantee. Hash folding
retains exact original canonical framing, provenance hash versus
membership priority and actual link/digest checks.

Output and scratch are disjoint 168 and 16,544-byte extents, respectively.
The larger reused private hash transcript ends by offset 11,258,
before the index banks [12,288,16,384); retained digest slots follow
those banks. All refusals preserve the entire output and input; scratch
may change during checked membership or hashing. The private scratch
guard runs after structural/header/source checks, before any indexing;
the private output-capacity guard runs before final digest publication.
There are no production, network, live store or release execution effects.

The test invokes locked original Cargo with a callback which always
rejects, then compares both stock native emitters with real full-size
fixtures, including the old extent cut, long common prefixes, same
name/version search ordering, competing invalid/duplicate observations,
and 257-row refusal. Wall timings include local fixture harness
overhead and are measurements, not acceptance deadlines.
