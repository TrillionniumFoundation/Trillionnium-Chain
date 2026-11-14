# Preserved pre-mutation evidence-child admission failure

The first admission used the actual v2 driver and exited 1 because its assumed transient Cargo lock file did not exist. It stopped before copying, staging or committing any repository file; its captured state remained clean 2d72fa3293989b01596ec8ce0ba3ff370dc4c584. All original stdout/stderr, attempts, owner records, command receipts, failure snapshot, exact used driver/inputs and complete 2,025-byte PTY output remain in the archive and manifest.

All native and source-gate owners had released the checkout. The continuation uses a dedicated lock outside the repository for this evidence-only operation. It performs no build and no test. The original frozen eleven-file F publication stage stays byte-identical and is separately described by publication-manifest.json; the admission input map also binds this additional failed-operation evidence.
