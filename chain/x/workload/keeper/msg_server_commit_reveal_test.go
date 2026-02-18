package keeper_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"chain/testutil/sample"
	"chain/x/workload/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/stretchr/testify/require"
)

func TestCommitRevealFlow(t *testing.T) {
	k, srv, ctx := setupMsgServer(t)
	creator := sample.AccAddress()
	worker := sample.AccAddress()

	wctx := sdk.WrapSDKContext(sdk.UnwrapSDKContext(ctx).WithBlockHeight(10))
	_, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator, Bounty: 1})
	require.NoError(t, err)
	k.SetWorker(wctx, types.Worker{Creator: worker, Stake: 100000})
	_, err = srv.AcceptTask(wctx, &types.MsgAcceptTask{Creator: worker, TaskId: 0})
	require.NoError(t, err)

	revealSalt := "salt-1"
	resultHash := "res-hash-1"
	commit := testCommitHash(0, resultHash, revealSalt, worker)

	_, err = srv.CommitResult(wctx, &types.MsgCommitResult{Creator: worker, TaskId: 0, CommitHash: commit})
	require.NoError(t, err)

	task, found := k.GetTask(wctx, 0)
	require.True(t, found)
	require.Equal(t, worker, task.Worker)
	require.Equal(t, commit, task.CommitHash)
	require.Equal(t, uint64(10)+k.GetParams(wctx).RevealWindowBlocks, task.RevealDeadlineHeight)

	_, err = srv.RevealResult(wctx, &types.MsgRevealResult{Creator: worker, TaskId: 0, ResultHash: resultHash, ResultUri: "ipfs://result", RevealSalt: revealSalt})
	require.NoError(t, err)

	task, found = k.GetTask(wctx, 0)
	require.True(t, found)
	require.Equal(t, types.TaskStatusResultSubmitted, task.Status)
	require.Equal(t, resultHash, task.ResultHash)
	require.Equal(t, "ipfs://result", task.ResultUri)
}

func TestRevealRejectsHashMismatch(t *testing.T) {
	k, srv, ctx := setupMsgServer(t)
	creator := sample.AccAddress()
	worker := sample.AccAddress()

	wctx := sdk.WrapSDKContext(sdk.UnwrapSDKContext(ctx).WithBlockHeight(20))
	_, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator, Bounty: 1})
	require.NoError(t, err)
	k.SetWorker(wctx, types.Worker{Creator: worker, Stake: 100000})
	_, err = srv.AcceptTask(wctx, &types.MsgAcceptTask{Creator: worker, TaskId: 0})
	require.NoError(t, err)

	_, err = srv.CommitResult(wctx, &types.MsgCommitResult{Creator: worker, TaskId: 0, CommitHash: testCommitHash(0, "good", "salt-a", worker)})
	require.NoError(t, err)

	_, err = srv.RevealResult(wctx, &types.MsgRevealResult{Creator: worker, TaskId: 0, ResultHash: "bad", RevealSalt: "salt-b"})
	require.ErrorIs(t, err, sdkerrors.ErrInvalidRequest)
}

func TestCommitRejectsNonAssignedWorker(t *testing.T) {
	k, srv, ctx := setupMsgServer(t)
	creator := sample.AccAddress()
	assignedWorker := sample.AccAddress()
	otherWorker := sample.AccAddress()

	wctx := sdk.WrapSDKContext(sdk.UnwrapSDKContext(ctx).WithBlockHeight(30))
	_, err := srv.CreateTask(wctx, &types.MsgCreateTask{Creator: creator, Bounty: 1})
	require.NoError(t, err)

	k.SetWorker(wctx, types.Worker{Creator: assignedWorker, Stake: 100000})
	_, err = srv.AcceptTask(wctx, &types.MsgAcceptTask{Creator: assignedWorker, TaskId: 0})
	require.NoError(t, err)

	_, err = srv.CommitResult(wctx, &types.MsgCommitResult{Creator: otherWorker, TaskId: 0, CommitHash: "abc"})
	require.ErrorIs(t, err, types.ErrWorkerMismatch)
}

func testCommitHash(taskID uint64, resultHash, revealSalt, worker string) string {
	payload := fmt.Sprintf("%d|%s|%s|%s", taskID, resultHash, revealSalt, worker)
	h := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(h[:])
}
