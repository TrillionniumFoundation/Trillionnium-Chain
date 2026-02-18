package types

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
	paramtypes "github.com/cosmos/cosmos-sdk/x/params/types"
)

var _ paramtypes.ParamSet = (*Params)(nil)

// ParamKeyTable the param key table for launch module
func ParamKeyTable() paramtypes.KeyTable {
	return paramtypes.NewKeyTable().RegisterParamSet(&Params{})
}

var (
	KeyWorkloadDenom                 = []byte("WorkloadDenom")
	KeyChallengeWindowBlocks         = []byte("ChallengeWindowBlocks")
	KeyChallengeDeposit              = []byte("ChallengeDeposit")
	KeyChallengerSlashPercent        = []byte("ChallengerSlashPercent")
	KeyWorkerSlashPercentOnBadResult = []byte("WorkerSlashPercentOnBadResult")
)

// NewParams creates a new Params instance
func NewParams(
	workloadDenom string,
	challengeWindowBlocks uint64,
	challengeDeposit uint64,
	challengerSlashPercent uint64,
	workerSlashPercentOnBadResult uint64,
) Params {
	return Params{
		WorkloadDenom:                 workloadDenom,
		ChallengeWindowBlocks:         challengeWindowBlocks,
		ChallengeDeposit:              challengeDeposit,
		ChallengerSlashPercent:        challengerSlashPercent,
		WorkerSlashPercentOnBadResult: workerSlashPercentOnBadResult,
	}
}

// DefaultParams returns a default set of parameters
func DefaultParams() Params {
	return NewParams("utrnm", 100, 1_000_000, 10, 20)
}

// ParamSetPairs get the params.ParamSet
func (p *Params) ParamSetPairs() paramtypes.ParamSetPairs {
	return paramtypes.ParamSetPairs{
		paramtypes.NewParamSetPair(KeyWorkloadDenom, &p.WorkloadDenom, validateWorkloadDenom),
		paramtypes.NewParamSetPair(KeyChallengeWindowBlocks, &p.ChallengeWindowBlocks, validateNonZeroUint64("challenge window blocks")),
		paramtypes.NewParamSetPair(KeyChallengeDeposit, &p.ChallengeDeposit, validateNonZeroUint64("challenge deposit")),
		paramtypes.NewParamSetPair(KeyChallengerSlashPercent, &p.ChallengerSlashPercent, validatePercent("challenger slash percent")),
		paramtypes.NewParamSetPair(KeyWorkerSlashPercentOnBadResult, &p.WorkerSlashPercentOnBadResult, validatePercent("worker slash percent on bad result")),
	}
}

func validateWorkloadDenom(i interface{}) error {
	v, ok := i.(string)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}
	if v == "" {
		return fmt.Errorf("workload denom cannot be empty")
	}
	if err := sdk.ValidateDenom(v); err != nil {
		return fmt.Errorf("invalid workload denom %q: %w", v, err)
	}
	return nil
}

func validateNonZeroUint64(name string) func(interface{}) error {
	return func(i interface{}) error {
		v, ok := i.(uint64)
		if !ok {
			return fmt.Errorf("invalid parameter type for %s: %T", name, i)
		}
		if v == 0 {
			return fmt.Errorf("%s must be > 0", name)
		}
		return nil
	}
}

func validatePercent(name string) func(interface{}) error {
	return func(i interface{}) error {
		v, ok := i.(uint64)
		if !ok {
			return fmt.Errorf("invalid parameter type for %s: %T", name, i)
		}
		if v > 100 {
			return fmt.Errorf("%s must be between 0 and 100", name)
		}
		return nil
	}
}

// Validate validates the set of params
func (p Params) Validate() error {
	if err := validateWorkloadDenom(p.WorkloadDenom); err != nil {
		return err
	}
	if err := validateNonZeroUint64("challenge window blocks")(p.ChallengeWindowBlocks); err != nil {
		return err
	}
	if err := validateNonZeroUint64("challenge deposit")(p.ChallengeDeposit); err != nil {
		return err
	}
	if err := validatePercent("challenger slash percent")(p.ChallengerSlashPercent); err != nil {
		return err
	}
	if err := validatePercent("worker slash percent on bad result")(p.WorkerSlashPercentOnBadResult); err != nil {
		return err
	}
	return nil
}
