# G1-R2A exit criteria v1

R2-A can leave implementation-in-progress only after its focused Rust tests,
rustfmt, strict Clippy, parent G1-R1 gate, canonical-plan gate and pre-cutover
truth gate all pass from an authorized clean clone and are independently
reviewed. This does not complete R2-B or G1.
