package types

// DONTCOVER

import (
	sdkerrors "cosmossdk.io/errors"
)

// x/workload module sentinel errors
var (
	ErrInvalidSigner = sdkerrors.Register(ModuleName, 1100, "expected gov account as only signer for proposal message")
	ErrSample        = sdkerrors.Register(ModuleName, 1101, "sample error")

	ErrWorkerAlreadyRegistered     = sdkerrors.Register(ModuleName, 1102, "worker already registered")
	ErrWorkerNotFound              = sdkerrors.Register(ModuleName, 1103, "worker not found")
	ErrUnbondingAlreadyRequested   = sdkerrors.Register(ModuleName, 1104, "unbonding already requested")
	ErrUnbondingNotFound           = sdkerrors.Register(ModuleName, 1105, "unbonding request not found")
	ErrUnbondingCooldownNotReached = sdkerrors.Register(ModuleName, 1106, "unbonding cooldown not reached")
	ErrUnauthorizedSlash           = sdkerrors.Register(ModuleName, 1107, "only authority can slash worker")
	ErrUnauthorizedUnbondingExtend = sdkerrors.Register(ModuleName, 1108, "only authority can extend unbonding")
	ErrInvalidSlashPercent         = sdkerrors.Register(ModuleName, 1109, "slash percent must be between 1 and 50")
	ErrInvalidSlashAmount          = sdkerrors.Register(ModuleName, 1110, "slash amount is zero")
	ErrMinRemainingStakeViolation  = sdkerrors.Register(ModuleName, 1111, "slash would violate minimum remaining worker stake")
	ErrDirectUnregisterDisabled    = sdkerrors.Register(ModuleName, 1112, "direct unregister disabled; use request-unbonding then finalize-unbonding")
	ErrInvalidExtraBlocks          = sdkerrors.Register(ModuleName, 1113, "invalid extraBlocks value")
	ErrInvalidWorkloadDenom        = sdkerrors.Register(ModuleName, 1114, "invalid workload denom")
	ErrInvalidBlockHeight          = sdkerrors.Register(ModuleName, 1115, "invalid block height")
)
