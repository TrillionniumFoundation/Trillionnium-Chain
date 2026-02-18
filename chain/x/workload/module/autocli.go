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
				{
					RpcMethod: "WorkerAll",
					Use:       "list-worker",
					Short:     "List all worker",
				},
				{
					RpcMethod:      "Worker",
					Use:            "show-worker [id]",
					Short:          "Shows a worker",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "creator"}},
				},
				{
					RpcMethod: "UnbondingAll",
					Use:       "list-unbonding",
					Short:     "List all unbonding",
				},
				{
					RpcMethod:      "Unbonding",
					Use:            "show-unbonding [id]",
					Short:          "Shows a unbonding",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "creator"}},
				},
				{
					RpcMethod: "ChallengeAll",
					Use:       "list-challenge",
					Short:     "List all challenge",
				},
				{
					RpcMethod:      "Challenge",
					Use:            "show-challenge [id]",
					Short:          "Shows a challenge by id",
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
				{
					RpcMethod:      "RegisterWorker",
					Use:            "register-worker [node-id] [ipfs-addr]",
					Short:          "Send a register-worker tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "nodeId"}, {ProtoField: "ipfsAddr"}},
				},
				{
					RpcMethod:      "AcceptTask",
					Use:            "accept-task [task-id]",
					Short:          "Accept and assign a task to worker",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "taskId"}},
				},
				{
					RpcMethod:      "SlashWorker",
					Use:            "slash-worker [worker] [slash-percent]",
					Short:          "Send a slash-worker tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "worker"}, {ProtoField: "slashPercent"}},
				},
				{
					RpcMethod:      "UnregisterWorker",
					Use:            "unregister-worker",
					Short:          "Send a unregister-worker tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{},
				},
				{
					RpcMethod:      "RequestUnbonding",
					Use:            "request-unbonding",
					Short:          "Send a request-unbonding tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{},
				},
				{
					RpcMethod:      "FinalizeUnbonding",
					Use:            "finalize-unbonding",
					Short:          "Send a finalize-unbonding tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{},
				},
				{
					RpcMethod:      "ExtendUnbonding",
					Use:            "extend-unbonding [worker] [extra-blocks]",
					Short:          "Send a extend-unbonding tx",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "worker"}, {ProtoField: "extraBlocks"}},
				},
				{
					RpcMethod:      "CommitResult",
					Use:            "commit-result [task-id] [commit-hash]",
					Short:          "Commit result hash preimage",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "taskId"}, {ProtoField: "commitHash"}},
				},
				{
					RpcMethod:      "RevealResult",
					Use:            "reveal-result [task-id] [result-hash] [result-uri] [reveal-salt]",
					Short:          "Reveal committed result",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "taskId"}, {ProtoField: "resultHash"}, {ProtoField: "resultUri"}, {ProtoField: "revealSalt"}},
				},
				{
					RpcMethod:      "SubmitResult",
					Use:            "submit-result [task-id] [result-hash] [result-uri]",
					Short:          "(legacy) submit task result and open challenge window",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "taskId"}, {ProtoField: "resultHash"}, {ProtoField: "resultUri"}},
				},
				{
					RpcMethod:      "ChallengeResult",
					Use:            "challenge-result [task-id] [reason] [evidence-uri]",
					Short:          "Challenge a submitted result",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "taskId"}, {ProtoField: "reason"}, {ProtoField: "evidenceUri"}},
				},
				{
					RpcMethod:      "ResolveChallenge",
					Use:            "resolve-challenge [task-id] [challenge-succeeded] [final-result-hash] [memo]",
					Short:          "Resolve challenge (authority only)",
					PositionalArgs: []*autocliv1.PositionalArgDescriptor{{ProtoField: "taskId"}, {ProtoField: "challengeSucceeded"}, {ProtoField: "finalResultHash"}, {ProtoField: "memo"}},
				},
				// this line is used by ignite scaffolding # autocli/tx
			},
		},
	}
}
