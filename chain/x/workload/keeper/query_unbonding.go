package keeper

import (
	"context"

	"chain/x/workload/types"
	"cosmossdk.io/store/prefix"
	"github.com/cosmos/cosmos-sdk/runtime"
	"github.com/cosmos/cosmos-sdk/types/query"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (k Keeper) UnbondingAll(ctx context.Context, req *types.QueryAllUnbondingRequest) (*types.QueryAllUnbondingResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	var unbondings []types.Unbonding

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	unbondingStore := prefix.NewStore(store, types.KeyPrefix(types.UnbondingKeyPrefix))

	pageRes, err := query.Paginate(unbondingStore, req.Pagination, func(key []byte, value []byte) error {
		var unbonding types.Unbonding
		if err := k.cdc.Unmarshal(value, &unbonding); err != nil {
			return err
		}

		unbondings = append(unbondings, unbonding)
		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAllUnbondingResponse{Unbonding: unbondings, Pagination: pageRes}, nil
}

func (k Keeper) Unbonding(ctx context.Context, req *types.QueryGetUnbondingRequest) (*types.QueryGetUnbondingResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	val, found := k.GetUnbonding(
		ctx,
		req.Creator,
	)
	if !found {
		return nil, status.Error(codes.NotFound, "not found")
	}

	return &types.QueryGetUnbondingResponse{Unbonding: val}, nil
}
