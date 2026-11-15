# Actual local deadline and native-crypto qualification

The retained logs compare the exact parent swarm implementation with the repair
using real localhost TCP, then execute actual ML-DSA-65 Python/C-provider and
Rust in-process EVP operations. See `local-qualification.json` for exact commands,
return codes, elapsed times, source blobs and installed tool versions.

`baseline-real-tcp.log` is an expected negative run: two deadline assertions fail
on parent `6f4b9cae0dafcb0e6bc171e2aa9b8f630e74eca6`. The new test harness is copied
into an isolated directory with that parent's original swarm/custody/envelope
source; no original repo content is overwritten for reproduction. Incomplete
attack responses never reach successful cryptographic verification.

`fixed-python.log` contains the six new deadline/cancellation/worker-reaping
tests plus the 39 retained real envelope/custody/swarm tests. Private test keys
are ephemeral and are not retained. The C crypto engine is the actual local
OpenSSL 3.5.9 build, not a substitute verifier.

`native-rust.log` and `native-clippy.log` cover the optional native Rust
ML-DSA-65 adapter and existing package tests with the locked graph. The opaque
verified frame has a compile-fail construction check. `native-format.log`
checks the two new Rust files without reformatting unrelated historical source.
The source-integrity positive and negative logs validate pins, not cryptography.

Scope: one local host/administrator, controlled test inputs, loopback TCP,
native cryptographic component. Not public WAN, model improvement, Hepta product
installation, account migration, consensus activation, independent acceptance,
hardware fault qualification or irreversible finality. All such flags remain
false. Any baseline errors are preserved rather than counted as successful
feature tests.
