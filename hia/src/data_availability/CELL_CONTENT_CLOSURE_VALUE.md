# Cell TCC2 declared content closure

This native owner checks and canonically re-emits complete TCC2 declarations
from a single immutable supplied loan. It matches the frozen pure
`CellContentClosureV2::{decode, validate, encode}` and its borrowed
dependency claims. Neither TCC2 nor this owner establishes that any declared
content exists, matches a claim, or may be loaded or adopted.

`f0(readbuf, mutbuf, mutbuf) -> u32` reads 1,457 through 1,520 bytes:
`TCC2 || BE32 TCM2 length || complete TCM2 || five (role, CCH1) slots`.
Outer, TCM2, and CCH1 extents are exact. Slot roles are the original 1–5
(Base, Parent, Tokenizer, Layout, Runtime) and must occur once in that order.
The same offset-aware TCM2 and CCH1 functions also underpin the standalone
TCM2 owner. The decoder checks the embedded manifest and every slot's role
tag and claim structure before checking any dependency purpose, profile or
size. It then checks each dependency in role order: ModelPayload purpose,
all 64 profile bytes equal to the manifest payload profile, and a
declared size from 1 byte through 64 GiB inclusive. The declared
generation, instance and digest are not converted into observation or
authority.

On success the canonical encoded bytes are copied exactly; all unfilled
output and all scratch are unchanged. On failure no output is written.
Codes 2–10 follow [TCM2 and CCH1](CELL_CONTENT_MANIFEST_VALUE.md); an invalid
dependency CCH1 uses the same original error class (6 encoding, 7 invalid
context) as the embedded payload. Codes 20–23 identify outer length,
version, exact coverage and role order; 26–28 are dependency purpose,
profile and size; 102 means the valid output would not fit.

Qualification uses the real frozen Cargo public original and both pinned
native backends. Fixtures are only synthetic declarations; no content
observation, payload reads, mutable state, networking, loader, provider
or proof of custody is involved.
