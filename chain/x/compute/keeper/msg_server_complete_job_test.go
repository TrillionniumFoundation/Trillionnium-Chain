package keeper_test

import (
	"testing"

	testutilkeeper "chain/testutil/keeper"
	"chain/testutil/sample"
	computekeeper "chain/x/compute/keeper"
	"chain/x/compute/types"
	workloadtypes "chain/x/workload/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestCompleteJob_Integration(t *testing.T) {
	k, workloadK, ctx := testutilkeeper.ComputeKeeperWithWorkload(t)
	msgServer := computekeeper.NewMsgServerImpl(k)
	goCtx := sdk.WrapSDKContext(ctx)

	worker := sample.AccAddress()
	otherWorker := sample.AccAddress()

	workloadK.SetWorker(ctx, workloadtypes.Worker{Creator: worker, Stake: 100000})
	workloadK.SetWorker(ctx, workloadtypes.Worker{Creator: otherWorker, Stake: 100000})

	createAndRun := func(t *testing.T) uint64 {
		createResp, err := msgServer.CreateComputeJob(goCtx, &types.MsgCreateComputeJob{
			Creator:      worker,
			Payload:      "ipfs://demo-task",
			Requirements: "cpu:2,ram:4gb",
		})
		require.NoError(t, err)

		_, err = msgServer.RequestJobExecution(goCtx, &types.MsgRequestJobExecution{
			Creator: worker,
			JobId:   createResp.JobId,
		})
		require.NoError(t, err)
		return createResp.JobId
	}

	t.Run("success", func(t *testing.T) {
		jobID := createAndRun(t)
		resp, err := msgServer.CompleteJob(goCtx, &types.MsgCompleteJob{
			Creator: worker,
			JobId:   jobID,
			Result:  "sha256:result-hash",
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		require.Equal(t, types.JobStatus_JOB_STATUS_COMPLETED, resp.Status)

		job, found := k.GetJob(ctx, jobID)
		require.True(t, found)
		require.Equal(t, types.JobStatus_JOB_STATUS_COMPLETED, job.Status)

		task, found := workloadK.GetTask(ctx, job.TaskId)
		require.True(t, found)
		require.EqualValues(t, 2, task.Status)
		require.Equal(t, worker, task.Worker)
		require.Equal(t, "sha256:result-hash", task.ResultHash)
	})

	t.Run("fail_non_running_status", func(t *testing.T) {
		jobID := createAndRun(t)
		_, err := msgServer.CompleteJob(goCtx, &types.MsgCompleteJob{Creator: worker, JobId: jobID, Result: "sha256:first"})
		require.NoError(t, err)

		_, err = msgServer.CompleteJob(goCtx, &types.MsgCompleteJob{Creator: worker, JobId: jobID, Result: "sha256:again"})
		require.Error(t, err)
	})

	t.Run("fail_wrong_worker", func(t *testing.T) {
		jobID := createAndRun(t)
		_, err := msgServer.CompleteJob(goCtx, &types.MsgCompleteJob{
			Creator: otherWorker,
			JobId:   jobID,
			Result:  "sha256:bad",
		})
		require.Error(t, err)
	})

	t.Run("fail_job_not_found", func(t *testing.T) {
		_, err := msgServer.CompleteJob(goCtx, &types.MsgCompleteJob{
			Creator: worker,
			JobId:   999999,
			Result:  "sha256:none",
		})
		require.Error(t, err)
	})
}
