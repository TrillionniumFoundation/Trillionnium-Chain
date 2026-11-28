# Safetensors raw JSON visitor at 1 MiB

This standalone f0(readbuf, mutbuf, mutbuf) consumes exact Safetensors JSON
header bytes up to the original 1 MiB raw framing limit. It has the same
decoded TensorHeader projection, error categories and 128 tensor / 64
metadata private limits as the previously qualified 128 KiB visitor. Both
stock compiler and per-loan wrappers remain unchanged. The older parser,
framing and integrated readback artifacts are not changed.

The borrowed header is not copied. At most 255 decoded bytes of a name/key or
12 bytes of a known field name are produced in the short transient field
slot. Only decoded tensor names and metadata keys survive in the bounded
name arena for exact comparisons, sorting and duplicate rejection. Metadata
values are scanned by the original UTF-8/JSON scalar code and counted (up to
16,384 decoded bytes), with no temporary value copy.

Dtype is a string at this stage, not an admission decision. For any legal
dtype string, the parser records its position in the same immutable input
and its exact decoded length. It performs all validation and checks output
capacity before publishing. During publication it replays just those string
spans using the same scalar decode routine to emit the actual UTF-8 in
canonical sorted records. Unrecognized, empty and long dtype strings are
therefore preserved rather than silently truncated. This remains linear in
raw input plus bounded entry/key comparisons and the size of the returned
projection. Private scratch is 160,256 bytes, down from 291,072 bytes.

The output and statuses stay as documented for the previous standalone
visitor: LE64 count, then original sorted name/dtype strings with LE64 lengths,
LE64 rank and dimensions, and LE64 start/end. Metadata is validated but not
returned. 217 is a JSON refusal; 218 is a private extent/count limitation;
102 is capacity. On refusal the output remains unchanged.

The tests call the locked original exact private serde visitor, including
legitimate one-mebibyte metadata-dense and dtype-dense cases, deeply escaped
UTF-8 strings, exact capacity and distinct larger original-only cases. The
native result covers this header stage only. The existing integrated reader
still has its separate 128 KiB raw JSON limit, and neither visitor constitutes
a file validation, owner or admission decision, storage, or live reader.
