# G1-R2A static review findings v1

Pre-compile review requires the two receipt/error constructors used only by the
test authority to remain `#[cfg(test)]` or otherwise explicitly non-production
reachable, so strict `-D warnings` cannot hide an accidental live adapter.

The authorized Rust gate is the authority for confirming this and all other
compile/lint details; this note is not a passing result.
