# HCSN PFT research candidate identity readback

This independent Chain reader consumes the `pft-online-candidate-v1` object
from Hepta's `hcsn-pft-readout-research-v1` family. It imports no training
module or numerical package and invokes no native adoption or payment owner.

The public `SYNTHETIC_CANDIDATE.json` is an explicitly authored two-by-two
matrix fixture: `[[1.0, -2.5], [0.0, -0.0]]`. Its semantic digests are hashes
of synthetic labels and its batch digests do not claim real contributions.
Its `EXPECTED.json` is a separately retained fixture tuple. No training,
model quality or native compatibility is implied by this synthetic object.

The separate real-history integration readback uses the original nine forward
candidates from the current online-statistics engineering run over frozen
historical #7071 synthetic-source training caches. Candidate byte digests come
from the learning-side evidence inventory; contract, head and weight digests
come from each run's original `RESULT.json`; parent digests come from the
earlier ring `MANIFEST.json`. These are separately retained statements, not
authenticated third-party provenance. The production reader requires
caller-supplied expectations and never derives them from a submitted candidate.
Original private candidate weights and training shards remain in the existing
private archive; this public report retains only required identities and scope.

The reader rejects duplicate JSON keys, unknown fields, nonfinite numbers,
boolean integers, incompatible model families, unbounded dimensions, different
feature/normalization/objective/time contracts, mismatching raw canonical
strings, unsorted/duplicate batch names and out-of-range declared dimensions or counts.
It recomputes the exact little-endian binary64 row-order weight digest,
including signed zero. All three inner identities and the exact candidate
byte digest must match their separately retained expectations.

Fifteen actual controls passed with the final public synthetic fixture. The
earlier 15-control run with a locally retained private historical fixture is
preserved separately; it is not relabelled as a final-source result or added
to the final count. A separate integration readback
checked all nine original forward candidates against each run's result and
the corresponding historical parent manifest. All 27 input file byte counts
and SHA-256 values matched the preexisting evidence inventory. The nine tuples
matched; the complete scoped reports and their input pins are retained in
`NINE_PARENT_READBACK.json`. That check used 7,515,192 ns of wall time in this
environment; it is a metadata readback, not a training-speed measurement.

The candidate's Gram/rhs/yTy contributions are not supplied to this reader.
It therefore does not verify their provenance, the normal equations, reported
sample uniqueness, the learning execution or a gain on independent tasks.
Every report keeps those claims false, along with native compatibility,
current adoption/use, payment, consensus credit, execution authority and
production activation. The existing ordinary-model `dev_loop_identity` and
all native schemas and owners are unchanged. No automatic conversion exists.

The local original project preflight passed for all 26 package manifests.
The native Cargo/Clippy/format gates remain unexecuted in this environment,
which lacks Rust and only materializes selected exact source. This Draft is
an identity bridge for research evidence and grants no release qualification.
