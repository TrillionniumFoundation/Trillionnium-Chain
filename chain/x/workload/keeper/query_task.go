package keeper

import (
	"context"

	"chain/x/workload/types"
	"cosmossdk.io/store/prefix"
	"github.com/cosmos/cosmos-sdk/runtime"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/query"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (k Keeper) TaskAll(ctx context.Context, req *types.QueryAllTaskRequest) (*types.QueryAllTaskResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	var tasks []types.Task

	store := runtime.KVStoreAdapter(k.storeService.OpenKVStore(ctx))
	taskStore := prefix.NewStore(store, types.KeyPrefix(types.TaskKey))

	pageRes, err := query.Paginate(taskStore, req.Pagination, func(key []byte, value []byte) error {
		var task types.Task
		if err := k.cdc.Unmarshal(value, &task); err != nil {
			return err
		}

		tasks = append(tasks, task)
		return nil
	})

	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &types.QueryAllTaskResponse{Task: tasks, Pagination: pageRes}, nil
}

func (k Keeper) Task(ctx context.Context, req *types.QueryGetTaskRequest) (*types.QueryGetTaskResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request")
	}

	task, found := k.GetTask(ctx, req.Id)
	if !found {
		return nil, sdkerrors.ErrKeyNotFound
	}

	return &types.QueryGetTaskResponse{Task: task}, nil
}
