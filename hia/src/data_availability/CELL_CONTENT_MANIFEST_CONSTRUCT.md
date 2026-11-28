# Detached TCM2 construction from held inert bytes

This native owner matches frozen public
`CellContentManifestV2::from_observed_payload` after the exact original
`observe_bytes` over the one supplied immutable payload span. The frame
does not accept any payload claim length, digest or precomputed observation.
The original TCM2 declaration only binds these supplied bytes and their
declared metadata; it cannot establish custody, provenance, ownership,
authorization or suitability for a loader.

The sole `f0(readbuf, mutbuf, mutbuf) -> u32` frame is:
`CCH1 context prefix (141) || max reads BE64 || max bytes BE64 ||
family length U8 || family || five 32-byte aliases || inert supplied bytes`.
It uses the existing stock single-loan cap of 1 MiB on the entire frame,
not the much larger general Rust content-length bound. The context comes
from the caller independently and must be a typed ModelPayload context.
A fresh positive declared numeric allowance must accommodate exactly one
observation and content length plus one for the original EOF probe.
There is no actual budget side effect, persisted counter or external EOF
operation. The original Rust qualification uses only its in-memory slice.

After frame, typed context and budget checks, the legacy family must be
decodable UTF-8 and match the original ASCII spelling and 1-to-64-byte
limit. The original payload purpose precedes its nonempty condition. For
valid inputs the shared exact [CCH1 hash](CELL_CONTENT_CLOSURE_OBSERVE.md)
uses the original SHA-512 domain, derived CCH1 header and held inert bytes.
Output is the exact canonical TCM2 with 379–442 written bytes and an
unchanged suffix. The caller supplies at least that capacity and 131,232
private scratch bytes. Refusals do not publish any TCM2 or digest.

Codes 5, 8, 9 and 10 are legacy UTF-8, model family, payload purpose and
payload size respectively. Codes 30–32 and 35 are the independent context
or fresh budget classes. Invalid/truncated native frame and over-1-MiB
inputs return 100, short mutable capacity 102, internal hash failure 103.
No actual user/model/filesystem/network data, `verify_readers`, access
control, store/cache, custody, or production integration is part of this
owner.
