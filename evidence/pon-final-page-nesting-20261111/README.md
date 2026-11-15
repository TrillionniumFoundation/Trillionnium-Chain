# Final-page nested-wall diagnostic guard

Base: 528f9659cbde9d1b4f7aeb63747eca0475aef966 (#905). A malformed original report with submit_result wall longer than its enclosing client import was classified as observed_final_page_activation while described as nested. Qualification was already false. The new guard keeps this contradictory observation unknown. Only wall containment is checked; different calling-thread CPU scopes are not equated.

The same two negative subcases (one-nanosecond excess and a very large excess) failed against the exact parent reader on Mac; the candidate passes all 23 reader tests. No Rust, native campaign, resource limit, consensus, workload or qualification changed. The bundled logs and validation.json bind exact reader and test Git blobs; tests are not inherited to another head.

Full workspace/Cargo/Clippy/native/4-second/30-second campaigns were not run by this change. Original observations and #905 evidence are preserved. Four business metrics remain null/unknown. Draft / HOLD_NO_GO.
