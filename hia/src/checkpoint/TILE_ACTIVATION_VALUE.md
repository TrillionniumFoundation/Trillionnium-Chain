# Private checkpoint activation typed value
This private post-JSON layer implements the frozen original ordered shape,
token-field and hidden-hex checks. It is not the raw activation parser:
the original JSON, pin, schema/profile, digest text and runtime-observation
gates remain outside this wire. The operation grants no provenance,
training, model or material authority and performs no I/O.

Input is eight-byte `TAV1\0\0\0\0`, then seven little-endian u64 words:
the three shape coordinates, three lengths (token IDs, attention mask,
positions), and hidden-hex byte length; then the corresponding consecutive
u64 arrays and exact hex bytes. Each array is bounded by 64 elements; the
whole frame is capped at 296,512 bytes. Shape must be [1,t,576] for
1 ≤ t ≤ 64. All three arrays must have t elements; token IDs are <49,152,
all mask values 1, and positions exactly 0 through t−1. Hidden text
must be exactly t×576×8 lowercase ASCII hex bytes.

Output is the little-endian u64 token count and exact decoded F32LE
bit bytes. This stage does **not** check float finiteness; original
quantization assembly does that separately. The complete extent and
semantics are checked before publication; workspace is unused. Status
1/2/3 denote original shape/token/bits failure, 100 denotes private
wire shape, and 102 denotes output capacity. No failure changes output.

The oracle invokes actual original private `activation` in a verbatim
frozen module, with synthetic inert JSON surrounding fields and an
in-memory test pin. These fixture fields do not represent a real
runtime observation or provenance. Both stock native backends compare
all output bytes and error precedence. The adjacent existing quantizer
test independently adds original F32 half-step neighbors for k=0–129.
