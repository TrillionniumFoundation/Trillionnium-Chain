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

func (k Keeper) WorkerAll(ctx context.Context, req *types.QueryAllWorkerRequest) (*types.QueryAllWorkerResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	var workers []types.Worker

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	workerStore := prefix.NewStore(store, types.KeyPrefix(types.WorkerKeyPrefix))

	pageRes, err := query.Paginate(workerStore, req.Pagination, func(key []byte, value []byte) error {
		var worker types.Worker
		if err := k.cdc.Unmarshal(value, &worker); err != nil {
			return err
		}

		workers = append(workers, worker)
		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAllWorkerResponse{Worker: workers, Pagination: pageRes}, nil
}

func (k Keeper) Worker(ctx context.Context, req *types.QueryGetWorkerRequest) (*types.QueryGetWorkerResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	val, found := k.GetWorker(
		ctx,
		req.Creator,
	)
	if !found {
		return nil, status.Error(codes.NotFound, "not found")
	}

	return &types.QueryGetWorkerResponse{Worker: val}, nil
}
