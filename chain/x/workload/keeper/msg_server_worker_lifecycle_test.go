package keeper_test

import (
	"testing"

	"chain/testutil/sample"
	"chain/x/workload/keeper"
	"chain/x/workload/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestRegisterWorker(t *testing.T) {
	_, srv, ctx := setupMsgServer(t)
	wctx := sdk.UnwrapSDKContext(ctx)
	creator := sample.AccAddress()

	_, err := srv.RegisterWorker(wctx, &types.MsgRegisterWorker{Creator: creator, NodeId: "node-1", IpfsAddr: "/ip4/127.0.0.1/tcp/4001"})
	require.NoError(t, err)

	_, err = srv.RegisterWorker(wctx, &types.MsgRegisterWorker{Creator: creator, NodeId: "node-1", IpfsAddr: "/ip4/127.0.0.1/tcp/4001"})
	require.ErrorIs(t, err, types.ErrWorkerAlreadyRegistered)
}

func TestUnbondingFlow(t *testing.T) {
	_, srv, ctx := setupMsgServer(t)
	wctx := sdk.UnwrapSDKContext(ctx)
	creator := sample.AccAddress()

	_, err := srv.RegisterWorker(wctx, &types.MsgRegisterWorker{Creator: creator, NodeId: "node-2", IpfsAddr: "/ip4/127.0.0.1/tcp/4002"})
	require.NoError(t, err)

	_, err = srv.RequestUnbonding(wctx, &types.MsgRequestUnbonding{Creator: creator})
	require.NoError(t, err)

	_, err = srv.FinalizeUnbonding(wctx, &types.MsgFinalizeUnbonding{Creator: creator})
	require.ErrorIs(t, err, types.ErrUnbondingCooldownNotReached)

	sdkCtx := sdk.UnwrapSDKContext(ctx)
	sdkCtx = sdkCtx.WithBlockHeight(sdkCtx.BlockHeight() + int64(keeper.UnbondingPeriodBlocks) + 1)
	_, err = srv.FinalizeUnbonding(sdkCtx, &types.MsgFinalizeUnbonding{Creator: creator})
	require.NoError(t, err)
}

func TestExtendUnbondingUnauthorized(t *testing.T) {
	k, srv, ctx := setupMsgServer(t)
	wctx := sdk.UnwrapSDKContext(ctx)
	worker := sample.AccAddress()
	notAuthority := sample.AccAddress()

	k.SetUnbonding(wctx, types.Unbonding{Creator: worker, ReleaseHeight: 100, Amount: 100000})

	_, err := srv.ExtendUnbonding(wctx, &types.MsgExtendUnbonding{Creator: notAuthority, Worker: worker, ExtraBlocks: 10})
	require.ErrorIs(t, err, types.ErrUnauthorizedUnbondingExtend)
}
