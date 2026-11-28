# Private CellNative Policy canonical value
This emits original public `canonical(&Policy)` compact sorted-key JSON
for a bounded typed private wire. The action and tool fields are inert;
this neither authorizes nor executes actions or tools, trains, validates
owner/state/network context, or changes production routing.

The input begins with `CPV1\0\0\0\0` and eight little-endian u64 words:
abstain margin; action count (0–4); expert-row count (0–64); sampler
tag (0 ArgmaxLowest, 1 Sha256PositiveShift); Training presence (0/1);
and three tool-name lengths (u64::MAX for None, otherwise 0–128 ASCII
bytes). Immediately following are ordered action tags (one byte each:
0 Emit, 1 Stop, 2 Abstain, 3 ProposeTool); 257 feature-Boolean bytes;
expert rows of three Boolean bytes; the consecutive present tool-name
bytes; and the optional 3,124-byte Training body (the existing CTr1
input after its eight-byte magic). All Boolean slots are exactly 0/1.
The total immutable input is 329 through 4,033 bytes. No interpretation
of original policy-admission predicates is made, including constraints
on effective action lists, expert masks, margin and training parameters.

The caller provides 24,576 disjoint scratch bytes, sufficient for 18,760
nested Training JSON bytes, feature/expert Boolean vectors, 2,304 maximum
expanded tool-name bytes and all other fixed fields/length. Output is
an eight-byte little-endian u64 JSON length followed by exactly the
JSON bytes. Status 1 refuses the frame, 102 refuses output/arena
capacity. Neither publishes output; only insufficient output may
leave staged bytes in private scratch. Existing Training and Mask
entries retain their wire, output and status behavior.
