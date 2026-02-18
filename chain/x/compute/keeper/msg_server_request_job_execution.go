package keeper

import (
	"context"
	"fmt"

	"chain/x/compute/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (k msgServer) RequestJobExecution(goCtx context.Context, msg *types.MsgRequestJobExecution) (*types.MsgRequestJobExecutionResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// 1. Get the Job
	job, found := k.GetJob(ctx, msg.JobId)
	if !found {
		return nil, fmt.Errorf("job with id %d not found", msg.JobId)
	}

	// 2. Check Job Status
	if job.Status != types.JobStatus_JOB_STATUS_CREATED {
		return nil, fmt.Errorf("job %d is not in CREATED state, current state: %s", msg.JobId, job.Status)
	}

	// 3. Verify Worker Eligibility
	// We need to access workloadKeeper which is a field of Keeper.
	// Since msgServer embeds Keeper and they are in the same package, this is valid.
	_, found = k.workloadKeeper.GetWorker(ctx, msg.Creator)
	if !found {
		return nil, fmt.Errorf("worker %s not found in workload module", msg.Creator)
	}

	// 4. Update Job Status and Assigned Worker
	job.Status = types.JobStatus_JOB_STATUS_RUNNING
	job.AssignedWorker = msg.Creator

	// 5. Save the Job
	k.SetJob(ctx, job)

	return &types.MsgRequestJobExecutionResponse{
		Status: job.Status,
	}, nil
}
