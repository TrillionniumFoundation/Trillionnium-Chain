package types

const (
	TaskStatusOpen uint64 = iota
	TaskStatusAssigned
	TaskStatusCommitted
	TaskStatusRevealed
	TaskStatusChallenged
	TaskStatusCompleted
	TaskStatusSlashed
)

// Legacy alias kept for backward source compatibility.
const TaskStatusResultSubmitted = TaskStatusRevealed

const (
	ChallengeStatusOpen uint64 = iota
	ChallengeStatusSucceeded
	ChallengeStatusRejected
)
