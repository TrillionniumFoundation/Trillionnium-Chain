package types

const (
	TaskStatusOpen uint64 = iota
	TaskStatusResultSubmitted
	TaskStatusCompleted
	TaskStatusChallenged
	TaskStatusSlashed
	TaskStatusAssigned
)

const (
	ChallengeStatusOpen uint64 = iota
	ChallengeStatusSucceeded
	ChallengeStatusRejected
)
