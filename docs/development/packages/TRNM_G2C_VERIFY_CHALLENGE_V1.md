# G2C Verify/Challenge package v2 replay

Status: **MODULE_CLOSED_CANDIDATE for A14-owned candidate surfaces / G2C remains BLOCKED_UPSTREAM**

Exact source is recorded in `docs/evidence/g2c/G2C_SOURCE_MANIFEST_V2.json`. The accepted-authority boundary remains closed: all profiles are globally disabled, fallback is forbidden, and verification/challenge decisions have no economic, Order-reorg or PoCO-weight authority.

Closed local candidate gaps include deterministic re-execution, exact seven-profile resolution, evidence-before-backend ordering, forward challenge/one-appeal lifecycle, durable-outbox idempotency, response-loss retry, exact acknowledgement and ordered outbox commitment.

Remaining gaps are owner-bound to A11/A12/A13/A15/A16/A17 and accepted G1. No caller-supplied digest, local SQLite row or subjective opinion can substitute for DA, JMT, Order, settlement or production authority.
