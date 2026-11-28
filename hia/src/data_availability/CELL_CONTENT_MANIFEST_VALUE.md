# TCM2 Cell model manifest declaration

This private value codec validates the exact original bounded TCM2
declaration (379–442 bytes) and returns only its canonical storage bytes.
It is not TCM1 chunk transport, TCX1 metadata equality, or the TCV2
complete version table. The embedding CCH1 is the 213-byte typed
ModelPayload claim, not a trust marker or an observation of any payload.

Exact field/error order is total extent, TCM2 magic, family byte length,
full coverage, valid UTF-8, inner CCH1 encoding and nonzero profile/instance,
original ASCII family validation, ModelPayload purpose, and payload length
from 1 through 64 GiB. Generation, the five 32-byte legacy aliases, and
the 64-byte declared digest are preserved verbatim. This is why an
all-zero declared digest is not by itself rejected by original decode:
it remains an unverified declaration, not a content check.

Status 1–10 correspond to the above ordered checks. Output capacity
(102) is checked last. No refusal changes any loan. The stock third
scratch loan is unused; success copies exactly the admitted input bytes
without touching a result tail. No new capture, key or claim generation,
pin check, payload read, owner binding, model execution or activation.

Proof calls the actual public decode and encode of the unchanged locked
DA Rust crate. Both frozen HIA emitters test the full canonical bytes,
minimum and maximum lengths, claim fields, UTF-8/ASCII distinction and
compound failure priorities. Rust and HIA return bytes only on success.
