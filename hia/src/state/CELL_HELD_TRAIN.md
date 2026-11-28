# One-loan held Cell numeric execution and update

This private projection starts with held typed products, features,
expert masks, a recurrent memory vector, and old training coordinates.
One stock native call derives the active rows, evaluates integer loss
and gradients, and applies the selected masked batch update. It does not
accept any caller-authored ActiveRow, loss, gradient, scratch offset,
authority, or phase verdict. It does not run inference, tasks, tools,
sampling, proof verification, admission, adoption, or state commitment.

The new CTRX0001 input uses the 80-byte CTUP header positions for
row count (1–64), a required zero reserved word instead of loss,
optimizer presence, old step, and the five original numeric policy
words. Three planes of 3,084 words supply weight, old moment, and mask,
not gradients. Their shape and domain are the existing CTUP domain.
The next 32 bytes provide remaining steps and three bounded memory
words. Held 2,192-byte rows start at 74,128 in the exact CTRW0001
layout. All rows and fields, including the inactive suffix, are
validated before scratch or public output changes. Max input is
214,416 bytes; dry means all held rows are inactive, not an empty
submitted roster.

The used arena intervals are disjoint by construction. For c active
rows, the successful output is the contiguous scratch prefix:

1. B = 30,848 + 80c bytes, exact training loss/backward numeric layout.
2. 123,392 bytes, exact CTUP training-update numeric layout.
3. 40 + 24c bytes, active count, remaining steps, final memory,
   and original post-row memory per active row.

The internally prepared ActiveRows use a separate arena interval
[262,144, 262,144 + 2,096c). The shared backward kernel reads old
immutable input addresses below 262,144, or internally derived arena
addresses in that interval, through one scalar offset accessor. All
legacy validated row addresses are below 208,240 and no caller supplies
an offset or mode. All calls use the existing three disjoint borrowed
arguments; there is no readbuf cast, sub-loan, or allocation. The
update reads only the native-generated gradient at [8, 24,680)
and writes strictly above B. The output prefix ends at or before
160,936, and the full scratch extent at or before 396,288. On a dry call
the high interval is empty and only 154,280 scratch bytes are needed.

For a valid bounded profile the route/recurrence/loss math cannot
overflow the admitted domain. The private API checks exact shape,
all source and parameter bounds, and the original single active step
increment before opening the scratch writer. A dry call preserves
the optional prior optimizer including the maximum step. Returns are
0 success, 100 invalid typed input, 102 short borrowed extent, 201 step
overflow, 202 the defensive original moment bound, or 203 trained
weight out of range. Scratch capacity is checked before use; with
adequate scratch an arithmetic refusal precedes a short public output.
Public output commits only on complete success. A late refusal may
leave produced bounded private rows, projection, and earlier updates
in scratch, but never writes public output.

The fixed-address helper refactor preserves standalone backward and
CTRN0002 contracts without changing CTRW, CTUP, or the coordinate
ABI. Machine bytes may change even where all prior observations match.
The frozen comparison executes the complete original private execute
with Training Some, inert fixtures, no tool names, deterministic
ArgmaxLowest, and locked small Rust dependencies. It observes only
numeric route consequences, original loss/gradient/update stages,
and recurrent memory/remaining, not action, checkpoint, or authority
state.

    python3 -B -m unittest -v hia.tests.test_cell_held_train
