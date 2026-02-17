package keeper_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	keepertest "chain/testutil/keeper"
	"chain/x/compute/types"
)

func TestGetParams(t *testing.T) {
	k, ctx := keepertest.ComputeKeeper(t)
	params := types.DefaultParams()

	require.NoError(t, k.SetParams(ctx, params))
	require.EqualValues(t, params, k.GetParams(ctx))
}

func TestSetParams_ValidateCalled(t *testing.T) {
	k, ctx := keepertest.ComputeKeeper(t)
	params := types.DefaultParams()

	require.NoError(t, params.Validate())
	require.NoError(t, k.SetParams(ctx, params))
}
