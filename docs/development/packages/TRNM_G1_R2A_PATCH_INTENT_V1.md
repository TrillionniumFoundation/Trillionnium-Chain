# G1-R2A patch intent v1

Before authorized Clippy, the private test-only Core receipt/error constructors
must either be compiled only under `cfg(test)` or referenced solely through a
sealed internal authority helper. They must never be made public merely to
silence dead-code warnings.
