package types

import "context"

type DisputeResolveInput struct {
	Task              Task
	Challenge         Challenge
	ChallengeSucceeded bool
	FinalResultHash   string
	Memo              string
}

type DisputeResolveOutput struct {
	ChallengeStatus uint64
	TaskStatus      uint64
	FinalResultHash string
}

type DisputeResolver interface {
	Resolve(ctx context.Context, in DisputeResolveInput) (DisputeResolveOutput, error)
}
