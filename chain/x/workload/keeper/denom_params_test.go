package keeper_test

import (
	"testing"

	"chain/x/workload/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestWorkloadDenomFromParams(t *testing.T) {
	k, _, ctx := setupMsgServer(t)
	sdkCtx := sdk.UnwrapSDKContext(ctx)

	params := k.GetParams(sdkCtx)
	require.Equal(t, "utrnm", params.WorkloadDenom)

	params.WorkloadDenom = "ufoo"
	err := k.SetParams(sdkCtx, params)
	require.NoError(t, err)

	updated := k.GetParams(sdkCtx)
	require.Equal(t, "ufoo", updated.WorkloadDenom)
}

func TestParamsValidateWorkloadDenom(t *testing.T) {
	p := types.DefaultParams()
	require.NoError(t, p.Validate())

	p.WorkloadDenom = ""
	require.Error(t, p.Validate())
}
