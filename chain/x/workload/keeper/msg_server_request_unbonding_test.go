package keeper_test

import (
	"strconv"
	"testing"

	"chain/testutil/sample"
	"chain/x/workload/keeper"
	"chain/x/workload/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func eventHasKV(events sdk.Events, eventType, key, value string) bool {
	for _, e := range events {
		if e.Type != eventType {
			continue
		}
		for _, attr := range e.Attributes {
			if string(attr.Key) == key && string(attr.Value) == value {
				return true
			}
		}
	}
	return false
}

func TestRequestUnbonding_StoresCooldownAndEmitsEvent(t *testing.T) {
	k, srv, ctx := setupMsgServer(t)
	sdkCtx := sdk.UnwrapSDKContext(ctx).WithBlockHeight(123)
	worker := sample.AccAddress()

	k.SetWorker(sdkCtx, types.Worker{Creator: worker, NodeId: "node-1", IpfsAddr: "/ip4/127.0.0.1/tcp/4001", Stake: 100000})

	_, err := srv.RequestUnbonding(sdkCtx, &types.MsgRequestUnbonding{Creator: worker})
	require.NoError(t, err)

	u, found := k.GetUnbonding(sdkCtx, worker)
	require.True(t, found)
	require.Equal(t, uint64(123)+keeper.UnbondingPeriodBlocks, u.ReleaseHeight)
	require.Equal(t, uint64(100000), u.Amount)

	_, workerStillExists := k.GetWorker(sdkCtx, worker)
	require.False(t, workerStillExists)

	expectedReleaseHeight := strconv.FormatUint(uint64(123)+keeper.UnbondingPeriodBlocks, 10)
	require.True(t, eventHasKV(sdkCtx.EventManager().Events(), "workload_request_unbonding", "worker", worker))
	require.True(t, eventHasKV(sdkCtx.EventManager().Events(), "workload_request_unbonding", "release_height", expectedReleaseHeight))
	require.True(t, eventHasKV(sdkCtx.EventManager().Events(), "workload_request_unbonding", "amount", "100000"))
}

func TestRequestUnbonding_AlreadyRequested(t *testing.T) {
	k, srv, ctx := setupMsgServer(t)
	sdkCtx := sdk.UnwrapSDKContext(ctx)
	worker := sample.AccAddress()

	k.SetWorker(sdkCtx, types.Worker{Creator: worker, Stake: 100000})
	k.SetUnbonding(sdkCtx, types.Unbonding{Creator: worker, ReleaseHeight: 222, Amount: 100000})

	_, err := srv.RequestUnbonding(sdkCtx, &types.MsgRequestUnbonding{Creator: worker})
	require.ErrorIs(t, err, types.ErrUnbondingAlreadyRequested)
}
