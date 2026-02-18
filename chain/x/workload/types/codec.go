package types

import (
	cdctypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/msgservice"
	// this line is used by starport scaffolding # 1
)

func RegisterInterfaces(registry cdctypes.InterfaceRegistry) {
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgCreateTask{},
		&MsgUpdateTask{},
		&MsgDeleteTask{},
	)
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgRegisterWorker{},
	)
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgSlashWorker{},
	)
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgUnregisterWorker{},
	)
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgRequestUnbonding{},
	)
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgFinalizeUnbonding{},
	)
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgExtendUnbonding{},
	)
	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgSubmitResult{},
		&MsgChallengeResult{},
		&MsgResolveChallenge{},
	)
	// this line is used by starport scaffolding # 3

	registry.RegisterImplementations((*sdk.Msg)(nil),
		&MsgUpdateParams{},
	)
	msgservice.RegisterMsgServiceDesc(registry, &_Msg_serviceDesc)
}
