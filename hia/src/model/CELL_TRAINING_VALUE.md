# Private CellNative training value and trainable mask
This entry emits the original public `canonical(&Training)` and
`canonical(&TrainableMask)` compact sorted-key JSON. Only the typed
fixed-size value geometry is supported. No configuration is admitted or
executed; in particular zero denominators are serializable values here,
not permission or a statement that a training calculation is defined.

The private input begins with `CTm1\0\0\0\0` (mask only) or
`CTr1\0\0\0\0` (training value). Training has five little-endian u64
values in canonical key order: clipping magnitude, learning rate
denominator then numerator, momentum denominator then numerator. Both
profiles end in exactly four row-major masks (base and three ordered
deltas). Each has three rows by 257 columns and exactly one byte per
Boolean, either 0 or 1. Exact input lengths are 3,092 and 3,132 bytes.

Output is an eight-byte little-endian u64 JSON length followed by the
exact JSON. The caller supplies 18,944 bytes of disjoint private scratch:
3,084 Boolean spellings have at most five bytes each; the remaining
arena covers commas, brackets, keys and five u64 decimal values. Status
1 refuses the frame and 102 refuses capacity. Neither publishes output.
A short output may leave staged bytes in private scratch.
