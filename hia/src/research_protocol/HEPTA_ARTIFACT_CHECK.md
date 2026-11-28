# Private offline Hepta artifact value checks

This separate pure status entry reproduces public original
HeptaArtifactAdmissionV1::validate and validate_at on typed inert records.
A 456-byte existing HAV1 frame invokes the field checks; the identical
frame followed by 8 little-endian supplied now bytes (464 total) also
invokes the inclusive time window. No system clock is read.

It checks the operation key and 11 required digests in original field
order, then the generation and parent relationship, positive payload
extent at most 64 MiB, nonzero ordered endpoints, and only then the
supplied window. Status 0 is shape/time only. Statuses 1–12 identify
the ordered required fields; 13 generation zero; 14 unexpected parent
at generation one; 15 missing later parent; 16 zero parent; 17 payload
extent; 18 endpoints; 19 before creation; 20 after expiry; 100 private
wire shape. The two mutable ABI spans are unused, including empty spans.
The entire input and any supplied buffers remain unchanged on every result.

The original locked public Rust library is called only on generated
records with explicit fixed time values, including conflicting first
errors, both inclusive endpoints, and unsigned extrema. Both stock HIA
emitters execute the same private check. This makes no signature, owner
validation, actual admission decision, claim of permission, or
production change. The prior canonical byte/digest entry is unchanged.
