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
	t.Run("default valid", func(t *testing.T) {
		p := types.DefaultParams()
		require.NoError(t, p.Validate())
	})

	t.Run("empty invalid", func(t *testing.T) {
		p := types.DefaultParams()
		p.WorkloadDenom = ""
		require.Error(t, p.Validate())
	})

	t.Run("sdk-invalid denom rejected", func(t *testing.T) {
		p := types.DefaultParams()
		p.WorkloadDenom = "1bad"
		err := p.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid workload denom")
	})

	t.Run("sdk-valid ibc denom remains compatible", func(t *testing.T) {
		p := types.DefaultParams()
		p.WorkloadDenom = "ibc/1234567890ABCDEF"
		require.NoError(t, p.Validate())
	})
}
