package workload

import (
	"math/rand"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/module"
	simtypes "github.com/cosmos/cosmos-sdk/types/simulation"
	"github.com/cosmos/cosmos-sdk/x/simulation"

	"chain/testutil/sample"
	workloadsimulation "chain/x/workload/simulation"
	"chain/x/workload/types"
)

// avoid unused import issue
var (
	_ = workloadsimulation.FindAccount
	_ = rand.Rand{}
	_ = sample.AccAddress
	_ = sdk.AccAddress{}
	_ = simulation.MsgEntryKind
)

const (
	opWeightMsgCreateTask = "op_weight_msg_task"
	// TODO: Determine the simulation weight value
	defaultWeightMsgCreateTask int = 100

	opWeightMsgUpdateTask = "op_weight_msg_task"
	// TODO: Determine the simulation weight value
	defaultWeightMsgUpdateTask int = 100

	opWeightMsgDeleteTask = "op_weight_msg_task"
	// TODO: Determine the simulation weight value
	defaultWeightMsgDeleteTask int = 100

	// this line is used by starport scaffolding # simapp/module/const
)

// GenerateGenesisState creates a randomized GenState of the module.
func (AppModule) GenerateGenesisState(simState *module.SimulationState) {
	accs := make([]string, len(simState.Accounts))
	for i, acc := range simState.Accounts {
		accs[i] = acc.Address.String()
	}
	workloadGenesis := types.GenesisState{
		Params: types.DefaultParams(),
		TaskList: []types.Task{
			{
				Id:      0,
				Creator: sample.AccAddress(),
			},
			{
				Id:      1,
				Creator: sample.AccAddress(),
			},
		},
		TaskCount: 2,
		// this line is used by starport scaffolding # simapp/module/genesisState
	}
	simState.GenState[types.ModuleName] = simState.Cdc.MustMarshalJSON(&workloadGenesis)
}

// RegisterStoreDecoder registers a decoder.
func (am AppModule) RegisterStoreDecoder(_ simtypes.StoreDecoderRegistry) {}

// ProposalContents doesn't return any content functions for governance proposals.
func (AppModule) ProposalContents(_ module.SimulationState) []simtypes.WeightedProposalContent {
	return nil
}

// WeightedOperations returns the all the gov module operations with their respective weights.
func (am AppModule) WeightedOperations(simState module.SimulationState) []simtypes.WeightedOperation {
	operations := make([]simtypes.WeightedOperation, 0)

	var weightMsgCreateTask int
	simState.AppParams.GetOrGenerate(opWeightMsgCreateTask, &weightMsgCreateTask, nil,
		func(_ *rand.Rand) {
			weightMsgCreateTask = defaultWeightMsgCreateTask
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgCreateTask,
		workloadsimulation.SimulateMsgCreateTask(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgUpdateTask int
	simState.AppParams.GetOrGenerate(opWeightMsgUpdateTask, &weightMsgUpdateTask, nil,
		func(_ *rand.Rand) {
			weightMsgUpdateTask = defaultWeightMsgUpdateTask
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgUpdateTask,
		workloadsimulation.SimulateMsgUpdateTask(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	var weightMsgDeleteTask int
	simState.AppParams.GetOrGenerate(opWeightMsgDeleteTask, &weightMsgDeleteTask, nil,
		func(_ *rand.Rand) {
			weightMsgDeleteTask = defaultWeightMsgDeleteTask
		},
	)
	operations = append(operations, simulation.NewWeightedOperation(
		weightMsgDeleteTask,
		workloadsimulation.SimulateMsgDeleteTask(am.accountKeeper, am.bankKeeper, am.keeper),
	))

	// this line is used by starport scaffolding # simapp/module/operation

	return operations
}

// ProposalMsgs returns msgs used for governance proposals for simulations.
func (am AppModule) ProposalMsgs(simState module.SimulationState) []simtypes.WeightedProposalMsg {
	return []simtypes.WeightedProposalMsg{
		simulation.NewWeightedProposalMsg(
			opWeightMsgCreateTask,
			defaultWeightMsgCreateTask,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				workloadsimulation.SimulateMsgCreateTask(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgUpdateTask,
			defaultWeightMsgUpdateTask,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				workloadsimulation.SimulateMsgUpdateTask(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		simulation.NewWeightedProposalMsg(
			opWeightMsgDeleteTask,
			defaultWeightMsgDeleteTask,
			func(r *rand.Rand, ctx sdk.Context, accs []simtypes.Account) sdk.Msg {
				workloadsimulation.SimulateMsgDeleteTask(am.accountKeeper, am.bankKeeper, am.keeper)
				return nil
			},
		),
		// this line is used by starport scaffolding # simapp/module/OpMsg
	}
}
