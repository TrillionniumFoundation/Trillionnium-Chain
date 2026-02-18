package keeper_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	sdk "github.com/cosmos/cosmos-sdk/types"

	computekeeper "chain/x/compute/keeper"
	"chain/x/compute/types"
	testutilkeeper "chain/testutil/keeper"
)

func TestCreateComputeJob_Integration(t *testing.T) {
	// 1. Setup Environment (Compute + Workload)
	// ComputeKeeperWithWorkload returns (computeKeeper, workloadKeeper, ctx)
	k, workloadK, ctx := testutilkeeper.ComputeKeeperWithWorkload(t)
	
	// Initialize MsgServer
	msgServer := computekeeper.NewMsgServerImpl(k)
	
	// Create context.Context from sdk.Context
	goCtx := sdk.WrapSDKContext(ctx)

	creator := "cosmos1j7pe3db767c2936y2a3d3c8x3c65c2q2y2w2w2"

	// 2. Test Case: Success
	t.Run("Success", func(t *testing.T) {
		msg := &types.MsgCreateComputeJob{
			Creator:      creator,
			Payload:      "ipfs://QmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR",
			Requirements: "cpu:2,ram:4gb",
		}

		resp, err := msgServer.CreateComputeJob(goCtx, msg)
		require.NoError(t, err)
		require.NotNil(t, resp)
		
		// 3. Verify Compute Job Exists
		job, found := k.GetJob(ctx, resp.JobId)
		require.True(t, found, "Compute Job should exist")
		require.Equal(t, msg.Creator, job.Creator)
		require.Equal(t, msg.Requirements, job.Requirements)
		require.Equal(t, msg.Payload, job.Payload)
		require.Equal(t, "Created", job.Status)

		// 4. Verify Workload Task Exists via TaskId from Job
		task, found := workloadK.GetTask(ctx, job.TaskId)
		require.True(t, found, "Workload Task should exist")
		require.Equal(t, msg.Payload, task.IpfsHash)
		require.Equal(t, msg.Creator, task.Creator)
	})

	// 5. Test Case: Validation Error (Empty Payload)
	t.Run("Fail_EmptyPayload", func(t *testing.T) {
		msg := &types.MsgCreateComputeJob{
			Creator:      creator,
			Payload:      "",
			Requirements: "cpu:2",
		}

		resp, err := msgServer.CreateComputeJob(goCtx, msg)
		require.Error(t, err)
		require.Nil(t, resp)
		require.ErrorIs(t, err, types.ErrInvalidPayload)
	})
}
