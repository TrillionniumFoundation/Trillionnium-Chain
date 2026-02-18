package keeper

import (
	"context"
	"strconv"

	"chain/x/compute/types"
	workloadtypes "chain/x/workload/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (k msgServer) CreateComputeJob(goCtx context.Context, msg *types.MsgCreateComputeJob) (*types.MsgCreateComputeJobResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)

	// Validate payload (simple non-empty check as per requirements)
	if msg.Payload == "" {
		return nil, types.ErrInvalidPayload
	}

	// Create a new task in the workload module
	task := workloadtypes.Task{
		IpfsHash: msg.Payload,
		Creator:  msg.Creator,
		Bounty:   0, // Default to 0 for now
		Status:   0, // Default status
	}

	// AppendTask returns the ID of the new task
	taskId := k.workloadKeeper.AppendTask(ctx, task)

	// Create and append the Compute Job
	job := types.Job{
		TaskId:       taskId,
		Creator:      msg.Creator,
		Requirements: msg.Requirements,
		Payload:      msg.Payload,
		Status:       types.JobStatus_JOB_STATUS_CREATED,
	}

	// AppendJob returns the ID of the new job
	jobId := k.AppendJob(ctx, job)

	ctx.EventManager().EmitEvent(
		sdk.NewEvent("new_compute_job",
			sdk.NewAttribute("job_id", strconv.FormatUint(jobId, 10)),
			sdk.NewAttribute("task_id", strconv.FormatUint(taskId, 10)),
			sdk.NewAttribute("creator", msg.Creator),
			sdk.NewAttribute("payload", msg.Payload),
			sdk.NewAttribute("requirements", msg.Requirements),
		),
	)

	return &types.MsgCreateComputeJobResponse{
		JobId: jobId,
	}, nil
}
