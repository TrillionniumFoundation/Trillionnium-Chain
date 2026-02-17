# Operations Manual

## Workload Module

### RequestUnbonding

The `RequestUnbonding` message allows a worker to initiate the process of unstaking their tokens.

#### Business Logic
1.  **Validation**:
    *   Checks if the request is valid (not nil).
    *   Verifies the creator address format.
    *   Checks if the worker exists (`ErrWorkerNotFound`).
    *   **Stake Check**: Verifies that the worker has a non-zero stake. If `Stake == 0`, the request is rejected with `ErrInvalidRequest` ("worker has no stake to unbond").
    *   Checks if an unbonding request already exists for the worker (`ErrUnbondingAlreadyRequested`).
    *   Verifies the block height is within safe bounds.

2.  **Execution**:
    *   Calculates the release height (`CurrentHeight + UnbondingPeriodBlocks`).
    *   Creates an `Unbonding` record with the calculated release height and the worker's current stake.
    *   Removes the `Worker` record immediately (worker exits active set).
    *   Emits a `workload_request_unbonding` event.

### Test Coverage
*   `x/workload/keeper`: ~92.7%
