# Standalone Safetensors JSON metadata roster

This candidate raises the standalone JSON visitor's metadata limit from 64
to the original 1,024 unique keys. It retains the 1 MiB raw header, original
255-byte decoded key and 16,384-byte decoded value lengths, and the previously
qualified 128-tensor limit. Metadata remains validated but is not returned.
No previously published JSON visitor or immutable reader is changed.

Each key is decoded once and stored once, alongside its exact decoded length.
The length/count/duplicate checks occur before inspecting the current value,
as in the original; 1,025 metadata entries produce the original generic JSON
refusal (217). Escaped and literal representations compare by exact decoded
UTF-8 bytes, including empty keys, prefixes, Unicode and NUL. This does not
normalize Unicode or use approximate hashes.

The stored sequence of key indices is a forest of sorted power-of-two runs.
A lookup binary-searches each occupied run, working backward along the
set bits in the current count. Before an insertion there are at most ten
runs; at most 55 comparisons are needed across them. An insertion appends
one index then merges equal-size consecutive runs. Across 1,024 insertions,
the merges contribute at most 9,217 comparisons. Comparisons themselves
examine at most 255 bytes per key. There are no full linear duplicate scans
or collision fallback paths.

Caller scratch is exactly 446,976 bytes: the previous 160,256-byte workspace,
1,024 fixed 264-byte key records, and two disjoint 8,192-byte index arrays.
Only initialized index/run slots are used. Input/output/scratch stay on the
unchanged stock `f0` ABI for both emitters. Refusals publish no projection.

The real unchanged, locked Rust private metadata visitor and both stock
emitters are compared at 1,024 keys in an exact non-padded 1 MiB header,
including worst-sized decoded names, escaped duplicates across all ten
runs, key/value limits, and the 1,025th-key refusal. The projected tensor
contents are unchanged. Exact statuses distinguish the narrower native raw
and tensor envelope from original JSON refusals; no finer error label is
reported. No reader, tensor payload, loader, path, authorization or
production behavior is in scope.
