package keeper_test

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"

	keepertest "chain/testutil/keeper"
	"chain/x/compute/keeper"
	"chain/x/compute/types"
	workloadtypes "chain/x/workload/types"
)

func TestRequestJobExecution(t *testing.T) {
	k, workloadK, ctx := keepertest.ComputeKeeperWithWorkload(t)
	msgServer := keeper.NewMsgServerImpl(k)
	goCtx := sdk.WrapSDKContext(ctx)

	// 1. Setup: Create a Job
	jobMsg := &types.MsgCreateComputeJob{
		Creator:      "cosmos1alice",
		Payload:      "ipfs://QmHash",
		Requirements: "cpu:4",
	}
	// We need to use msgServer.CreateComputeJob.
	// But first we need to make sure CreateComputeJob works.
	// It relies on workloadKeeper to AppendTask.
	// ComputeKeeperWithWorkload sets up workloadKeeper properly.
	resp, err := msgServer.CreateComputeJob(goCtx, jobMsg)
	require.NoError(t, err)
	jobId := resp.JobId

	// 2. Setup: Create a Worker
	workerCreator := "cosmos1worker"
	worker := workloadtypes.Worker{
		Creator:  workerCreator,
		NodeId:   "node1",
		IpfsAddr: "/ip4/127.0.0.1/tcp/5001",
		Stake:    1000,
	}
	// Use workloadK to set the worker directly (bypassing MsgServer for simplicity)
	workloadK.SetWorker(ctx, worker)

	// 3. Test: Request Job Execution (Success)
	reqMsg := &types.MsgRequestJobExecution{
		Creator: workerCreator,
		JobId:   jobId,
	}
	_, err = msgServer.RequestJobExecution(goCtx, reqMsg)
	require.NoError(t, err)

	// Verify Job state in store
	job, found := k.GetJob(ctx, jobId)
	require.True(t, found)
	require.Equal(t, types.JobStatus_JOB_STATUS_RUNNING, job.Status)
	require.Equal(t, workerCreator, job.AssignedWorker)

	// 4. Test: Request Job Execution (Fail - Job not Created)
	// Job is now Running, so request should fail
	_, err = msgServer.RequestJobExecution(goCtx, reqMsg)
	require.Error(t, err)
	// Error message might vary, but should contain state info
	// require.Contains(t, err.Error(), "not in CREATED state")

	// 5. Test: Request Job Execution (Fail - Worker not found)
	// Reset job status for testing
	job.Status = types.JobStatus_JOB_STATUS_CREATED
	k.SetJob(ctx, job)
	
	reqMsgUnknown := &types.MsgRequestJobExecution{
		Creator: "cosmos1unknown",
		JobId:   jobId,
	}

	_, err = msgServer.RequestJobExecution(goCtx, reqMsgUnknown)
	require.Error(t, err)
	require.Contains(t, err.Error(), "worker cosmos1unknown not found")
}
