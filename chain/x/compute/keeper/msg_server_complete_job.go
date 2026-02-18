package keeper

import (
	"context"
	"fmt"
	"strconv"

	"chain/x/compute/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (k msgServer) CompleteJob(goCtx context.Context, msg *types.MsgCompleteJob) (*types.MsgCompleteJobResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	job, found := k.GetJob(ctx, msg.JobId)
	if !found {
		return nil, fmt.Errorf("job with id %d not found", msg.JobId)
	}

	if job.Status != types.JobStatus_JOB_STATUS_RUNNING {
		return nil, fmt.Errorf("job %d is not in RUNNING state, current state: %s", msg.JobId, job.Status)
	}

	if job.AssignedWorker != msg.Creator {
		return nil, fmt.Errorf("only assigned worker can complete job: assigned=%s sender=%s", job.AssignedWorker, msg.Creator)
	}

	if err := k.workloadKeeper.CompleteTask(ctx, job.TaskId, msg.Creator, msg.Result); err != nil {
		return nil, err
	}

	job.Status = types.JobStatus_JOB_STATUS_COMPLETED
	k.SetJob(ctx, job)

	ctx.EventManager().EmitEvent(
		sdk.NewEvent("compute_complete_job",
			sdk.NewAttribute("job_id", strconv.FormatUint(msg.JobId, 10)),
			sdk.NewAttribute("task_id", strconv.FormatUint(job.TaskId, 10)),
			sdk.NewAttribute("worker", msg.Creator),
			sdk.NewAttribute("status", job.Status.String()),
		),
	)

	return &types.MsgCompleteJobResponse{
		JobId:  msg.JobId,
		Status: job.Status,
	}, nil
}
