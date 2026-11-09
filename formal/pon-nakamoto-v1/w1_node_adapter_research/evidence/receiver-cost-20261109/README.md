# Receiver-cost continuation, 2026-11-09

Base: `e2a02f9271b49f146e70806c8a66e161b5973971` (the #835 integration candidate).
This packet concerns the matched development-Node receiver implementation and
its verification. It does not activate production or qualify a whole-chain gain.

## Initial observations retained

- The original preflight passed on the isolated development branch with the
  unchanged 26-package inventory.
- The first partial checkout did not satisfy the complete source contract. Its
  full materialization attempt failed with ENOSPC. A separate early release
  compilation failed while writing a linker/code-generation object with ENOSPC.
  Neither is a successful build or benchmark.
- A subsequent materialization process terminated with exit 137. The unique
  cause of SIGKILL was not established. The executor then reported unavailable
  and recovery timed out. A zero-byte baseline checkout file was restored from
  the exact original Git object after recovery; no original evidence was changed.
- The recovered executor retained all five modified source/test files but did
  not retain the previously available Rust toolchain. The next build preparation
  failed before Cargo could start. Toolchain reinstallation and a new frozen-
  source build therefore have separate identities.
- One early Python test incorrectly assumed that a short-lived child had printed
  before a 0.15-second timeout. The test was corrected to verify the actual raw
  output bytes and hash, including a legitimately empty log. Timeout acceptance
  remains a failure. The final focused reader suite reported 17 tests passing;
  those synthetic/benign subprocess controls are not W1 proof or Node samples.
- HeptaRuntime returned an admitted-SSH-capacity refusal on a read-only lookup.
  Two ROG directory observations timed out with empty logs. The original CPU
  resource-evaluation request has unknown completion, with no cloud allocation,
  plan or execute request. Missing resource evidence is not a W1 result.

Original failed tool observations are not relabeled as complete process logs.
Subsequent validation receipts and benchmark manifests must identify their own
exact source, actual binary, inputs, resource observations and terminal outcomes.

## Open gates

Full source and dependency checks, native test execution, measured local receiver
results, same-resource deadline observations, actual network transport and the
production proof-replacement qualification are separate requirements. Until
their original evidence is present, their status remains pending or HOLD.
