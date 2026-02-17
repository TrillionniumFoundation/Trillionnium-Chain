package workload

import (
	autocliv1 "cosmossdk.io/api/cosmos/autocli/v1"

	modulev1 "chain/api/chain/workload"
)

// AutoCLIOptions implements the autocli.HasAutoCLIConfig interface.
func (am AppModule) AutoCLIOptions() *autocliv1.ModuleOptions {
	return &autocliv1.ModuleOptions{
		Query: &autocliv1.ServiceCommandDescriptor{
			Service: modulev1.Query_ServiceDesc.ServiceName,
			RpcCommandOptions: []*autocliv1.RpcCommandOptions{
				{
					RpcMethod: "Params",
					Use:       "params",
					Short:     "Shows the parameters of the module",
				},
				{
					RpcMethod: "TaskAll",
					Use:       "list-task",
					Short:     "List all task",
				},
				{
					RpcMethod:      "Task",
					Use:            "show-task [id]",
					Short:          "Shows a task by id",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "id"}},
				},
				// this line is used by ignite scaffolding # autocli/query
			},
		},
		Tx: &autocliv1.ServiceCommandDescriptor{
			Service:              modulev1.Msg_ServiceDesc.ServiceName,
			EnhanceCustomCommand: true, // only required if you want to use the custom command
			RpcCommandOptions: []*autocliv1.RpcCommandOptions{
				{
					RpcMethod: "UpdateParams",
					Skip:      true, // skipped because authority gated
				},
				{
					RpcMethod:      "CreateTask",
					Use:            "create-task",
					Short:          "Create task",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "ipfsHash"}, {ProtoField: "bounty"}, {ProtoField: "status"}, {ProtoField: "worker"}, {ProtoField: "resultHash"}},
				},
				{
					RpcMethod:      "UpdateTask",
					Use:            "update-task",
					Short:          "Update task",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "ipfsHash"}, {ProtoField: "bounty"}, {ProtoField: "status"}, {ProtoField: "worker"}, {ProtoField: "resultHash"}},
				},
				{
					RpcMethod: "DeleteTask",
					Use:       "delete-task",
					Short:     "Delete task",
				},
				// this line is used by ignite scaffolding # autocli/tx
			},
		},
	}
}
