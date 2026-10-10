# Initial selected matrix passed; additional counterexamples failed

Source: 93c0f02f2d1e8672a4a6c6204c5eecec3f08df25.
The selected-matrix subdirectory is a byte-for-byte copy of its successful per-command
qualification receipt, original manifest, experiments and raw logs. It does NOT cover
current runtime. The enclosing remote-tool wrapper reported exit 1 despite the inner
runner completion and zero recorded command exits; no wrapper-success claim is inferred.

Additional actual probes on that source reproduced two failures:
- An allowed 20-sample hot-sender benchmark ran out of test funds (FUNDS). The ledger
  correctly refused spending; the experiment generator had not funded its declared budget.
- A real reserved task at height 1, empty height 2 and refund at height 3 hit SESSION_RECEIPTS.
  The cache wrapper had incorrectly assumed one receipt per transaction, omitting the
  mandatory expiry prefix on an empty block. Earlier selected scenarios missed this case.

The logs remain unchanged. New tests and a new implementation fix both behaviors; the
entire qualification is rerun into a different directory. Old passes and failed probes
are not combined into one inflated success count or repinned to the repaired source.
