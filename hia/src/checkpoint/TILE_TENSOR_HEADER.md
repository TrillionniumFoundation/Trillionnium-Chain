# Bounded checkpoint-specific BF16 tensor metadata selection

The private stock entry takes `THV1\0\0\0\0`, a u64 little-endian declared
payload extent, then one immutable named-object safetensors header. It uses
the existing strict lexical scanner and decoded-key uniqueness. Named
entries are processed in decoded UTF-8 byte order, as in the original
frozen serde map, regardless of wire order. `__metadata__` maps only to
strings with a 4,096-byte decoded value limit.

The typed layer requires original closed records and u64 shapes/offsets,
ranks 1–8, nonzero dimensions below 2³¹, the original dtype-width table,
checked products and declared extents. The exact target
`model.layers.0.self_attn.q_proj.weight` must be BF16 with shape [576,576].
The entire positive interval set must form a gap-free, nonoverlapping union
from zero to the declared payload extent. Coverage precedes a missing
target; an invalid present target refuses during its sorted typed row.

This intentionally narrower private profile is at most 32 members per
map, 128 decoded bytes per key, primitive arrays of up to 64 entries,
named tensor records, and a 1 MiB complete frame (the original raw header
limit is 16 MiB, with broader valid names and typed forms). Deep JSON,
original true 129-byte names, positional Tensor arrays and non-object root
are private scope refusals, not claimed original errors. Tests execute the
full original private `tensor_header` with an inert test observer.

The disjoint output is three u64 little-endian values on success:
target start, target end, and tensor count excluding metadata. Output is
unchanged on refusal. Work requires 18,000 private bytes. Status 2 strict
JSON; 4 name; 5 metadata; 6 fields; 7 shape; 8 dtype; 9 target; 10 coverage;
11 extent; 100 framing; 102 capacity; 103 private profile. No file or
checkpoint data is read. No observer, proof, loader, material authority,
training or genuine model operation is represented.
