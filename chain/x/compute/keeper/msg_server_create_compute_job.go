package keeper

import (
	"context"

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
	id := k.workloadKeeper.AppendTask(ctx, task)

	return &types.MsgCreateComputeJobResponse{
		JobId: id,
	}, nil
}
