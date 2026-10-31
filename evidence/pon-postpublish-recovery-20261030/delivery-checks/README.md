# Whole-repository working-candidate check

The actual `python scripts/ci/check_repository.py` invocation returned exit zero
after recovery documentation was written. Its [stdout](repository-working-candidate.stdout.log)
records 26 workspace packages, 1,121 Rust files, 1,695 local links and 20 normal
dependency edges. [Stderr](repository-working-candidate.stderr.log) is empty.
The source is explicitly a dirty candidate based on local repair commit
`2d74588c1b7333751bbb555ff6a038d5a1f4fe23`; this is not a clean final-commit
source guard or native qualification. These two files are exact saved output,
not reconstructed execution records. No elapsed-time or resource receipt was
measured for this command.
