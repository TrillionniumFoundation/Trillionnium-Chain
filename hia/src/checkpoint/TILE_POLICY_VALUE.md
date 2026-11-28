# Private context-free checkpoint maintenance policy value
This bounded immutable value projection implements the original public
`CheckpointTilePolicySpecV1::canonical` and `id` for the maintenance-only
configuration. No material is opened or checked. No task, proof, operator,
deployment, W1, hardware or network path is evaluated or enabled.

The `TPV1\0\0\0\0` input has three little-endian u64 words: checkpoint
byte length, useful-output limit, and a flags bitset (bits 0–6 for
maintenance-only, chain-authority, hardness-accepted, genuine-demand,
full-forward, marginal-contribution and public-network-ready).
The remaining fields are the original fixed 38-byte schema, 64 lowercase
hex bytes of the exact original material-policy constant, and seven
64-byte lowercase hex identities, ordered checkpoint, activation, A, B,
model, input, matrix task. The exact frame is 582 bytes; other typed string
lengths are outside this wire. The Rust oracle gets the material-policy
literal from the original public `policy_id()`, never from this module.

The original sequence is policy/schema, file-length scalar (10–512 MiB),
all seven nonzero identities, then flags/useful-output. Only the original
maintenance-only true/all other false and useful-output zero can proceed.
The maximum serialized size of the fixed profile is below the original
32 KiB cap. Output is the little-endian u64 JSON length, 32-byte original
PoN-framed ID digest and sorted compact JSON. The unused suffix remains
untouched. The caller supplies 4,096 disjoint scratch bytes. Statuses
1–4 model the original field checks; 100 is wire/refusal, 102 capacity
and 103 internal hash. No refusal writes output.
