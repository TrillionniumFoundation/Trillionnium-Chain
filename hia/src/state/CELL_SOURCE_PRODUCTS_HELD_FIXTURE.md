# Synthetic text to held Cell numeric training

This fixture feeds two synthetic text byte strings, a model, and typed boolean
feature masks into the already separate source preprocessing, all-fifteen
scalar product, and held training kernels. It compares the three published
stock programs to actual frozen Rust, without a host feature or dot arithmetic
fallback. The private reference calls complete original `source::prepare` and
`execution::execute` with training enabled. Its scalar oracle uses the exact
Cell weight iterator and signed sum from the unchanged verification routine,
cross-checked with the original independent routed dot. Only those pure spans
are compiled, not that routine's W1 proof logic. No fixture has real task data,
a tool, a stochastic sampler, a source trust token, or authority.

The HIA runner gets the normalized bytes and both vectors from its exact
`CSP00001` outputs. It takes the 257 masked LE64 feature words at [2104,4160)
and exactly narrows them to the product kernel's LE32 words by checked
roundtrip. Model order is base, router, deltas 0/1/2. The product kernel emits
all fifteen signed LE64 words per row. Each `CTRX0001` row starts with the
synthetic typed expert mask and label, followed by those original native
output bytes and the unchanged CSP masked LE64 words. This explicit byte
packing has no memoized digest, host dot, or caller-supplied gradient.

The same two nontrivial text rows are used for two active rows, an active
prefix of one, and no remaining steps. All expected feature and product bytes
are computed from the original actual typed reference across all cases.
The reference's initial parser receives structural transport placeholders
for feature and product slots, but the data passed into original
`execute` are only the actual original preparation and actual scalar
products; native CTRX never receives the placeholders. The fixture compares
the entire return and stock prepared rows, including reporting changed model
coordinates for active cases and absent untouched optimizer in the dry case.
The dry case still preprocesses and produces all held lanes for both valid
submitted rows. Disjoint caller buffers and untouched tails are checked.

This is a synthetic arithmetic regression, not proof production, action
delivery, model adoption, a deployment or an evaluation against future
introduced data.
