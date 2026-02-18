package keeper

import (
	"context"

	"chain/x/workload/types"
)

type authorityResolver struct{}

func (authorityResolver) Resolve(_ context.Context, in types.DisputeResolveInput) (types.DisputeResolveOutput, error) {
	out := types.DisputeResolveOutput{
		FinalResultHash: in.Task.ResultHash,
	}
	if in.FinalResultHash != "" {
		out.FinalResultHash = in.FinalResultHash
	}

	if in.ChallengeSucceeded {
		out.TaskStatus = types.TaskStatusSlashed
		out.ChallengeStatus = types.ChallengeStatusSucceeded
	} else {
		out.TaskStatus = types.TaskStatusCompleted
		out.ChallengeStatus = types.ChallengeStatusRejected
	}
	return out, nil
}
