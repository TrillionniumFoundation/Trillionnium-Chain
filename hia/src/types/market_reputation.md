# M2 market reputation value operations

The [HIA component](market_reputation.hepta) ports the two pure public
[legacy Rust value operations](../../../trillionnium/crates/trnm-types/src/market_reputation.rs).
The score accepts four `u16` inputs: success, timeout, dispute, and penalty
events. Rate fields saturate independently at 10,000 bps; penalty event counts
are not saturated. The original score is the success rate less the timeout
rate, twice the dispute rate, and 200 bps per event, floored at zero.
The largest possible cost is 13,137,000, so the widened arithmetic cannot
overflow. A guarded subtraction avoids native unsigned underflow. Any positive
result is at most 10,000 and fits the returned `u16`.

The tier call accepts any `u16` score and returns a local ABI tag:
0 = Trusted (8,000–10,000), 1 = Watch (5,000–7,999), and 2 = Restricted
(everything else). In particular, classification does not clamp scores above
10,000. The tags are not a new wire format; original Rust Serde is not changed.
There are no current production callers of these two functions. This does not
migrate Worker behavior, matching, routing, admission, or Node ownership.

The [differential test](../../tests/test_market_reputation.py) builds the
original Rust value definitions using the pinned Rust toolchain, removing only
Serde import and derive annotations from the test copy. Both native machine-code
backends are compared against all 65,536 tier inputs and a bounded score corpus
of rate caps, penalty extremes and seeded boundary/full-domain inputs.
