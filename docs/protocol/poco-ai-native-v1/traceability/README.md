# W0-W7 traceability v1

Status: **candidate-non-normative**.

`tools/w0-w7-codegen/generate.py` consumes the pinned A08 operation registry
and emits exactly 30 rows.  Required links are obligations, not completion
claims.  A null evidence field is an open gap.  Disabled rows are identified
by their source `status` and terminate at W0; no fixed kind number is treated
as the sentinel.  Source/parser identity and deterministic evidence are
checked by `scripts/ci/check_w0_w7_traceability_v1.sh`.
