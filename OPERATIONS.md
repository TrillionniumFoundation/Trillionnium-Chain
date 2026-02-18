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


### FinalizeUnbonding

The `FinalizeUnbonding` message allows a user to claim their unbonded tokens after the unbonding period has elapsed.

#### Business Logic
1.  **Validation**:
    *   Checks if the request is valid (not nil).
    *   Verifies the creator address format.
    *   Checks if an `Unbonding` record exists for the creator (`ErrUnbondingNotFound`).
    *   Checks if the current block height has reached or exceeded the `ReleaseHeight` (`ErrUnbondingCooldownNotReached`).

2.  **Execution**:
    *   Retrieves the stored `Unbonding` amount.
    *   Transfers the unbonded tokens from the module account back to the user's account (via BankKeeper).
    *   Removes the `Unbonding` record from the store.
    *   Emits a `workload_finalize_unbonding` event.

#### State Consistency
*   **Worker Removal**: The `Worker` record is removed during `RequestUnbonding`. `FinalizeUnbonding` ensures that no "zombie" worker record exists.
*   **Unbonding Cleanup**: The `Unbonding` record is strictly removed upon successful finalization to prevent double spending.

### Test Coverage
*   `x/workload/keeper`: ~92.7%
*   New Test: `TestFinalizeUnbonding_StateConsistency` verifies that:
    1.  Worker record is removed after `RequestUnbonding`.
    2.  Unbonding record is created correctly.
    3.  After `FinalizeUnbonding`, both Worker and Unbonding records are absent.

## Compute Module

### CreateComputeJob

The `CreateComputeJob` message allows a user to submit a compute job which creates a task in the Workload module.

#### Business Logic
1.  **Validation**:
    *   Checks if the payload is empty (`ErrInvalidPayload`).
    *   Verifies the creator address format.

2.  **Execution**:
    *   Creates a `Task` in the Workload module with the provided payload as `IpfsHash`.
    *   Returns the new `JobId` (which corresponds to the Task ID in Workload module).

### Integration Test
*   `TestCreateComputeJob_Integration`:
    *   Verifies that calling `CreateComputeJob` creates a corresponding task in `Workload` module.
    *   Queries the task using the returned `JobId` to confirm side effects.
    *   Validates error handling for empty payload.
