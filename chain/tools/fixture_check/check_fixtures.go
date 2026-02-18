package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type SummaryV2 struct {
	SchemaVersion          int    `json:"schema_version"`
	Status                 string `json:"status"`
	Reason                 string `json:"reason"`
	Worker                 string `json:"worker"`
	LastStep               string `json:"last_step"`
	LastTx                 string `json:"last_tx"`
	TxRegister             string `json:"tx_register"`
	TxRequestUnbonding     string `json:"tx_request_unbonding"`
	TxFinalizeUnbonding    string `json:"tx_finalize_unbonding"`
	StartHeight            int64  `json:"start_height"`
	EndHeight              int64  `json:"end_height"`
	HeightDelta            int64  `json:"height_delta"`
	DurationS              int64  `json:"duration_s"`
	ReleaseHeight          int64  `json:"release_height"`
	CooldownWaitedBlocks   int64  `json:"cooldown_waited_blocks"`
	CooldownStagnantRounds int64  `json:"cooldown_stagnant_rounds"`
	NodeHeight             string `json:"node_height"`
	CatchingUp             string `json:"catching_up"`
}

type SummaryV3 struct {
	SchemaVersion int    `json:"schema_version"`
	Status        string `json:"status"`
	Reason        string `json:"reason"`
	Worker        string `json:"worker"`
	LastStep      string `json:"last_step"`
	LastTx        string `json:"last_tx"`
	// V3 might have these at top level too, but let's check nested
	PhaseTxs struct {
		Register          string `json:"register"`
		RequestUnbonding  string `json:"request_unbonding"`
		FinalizeUnbonding string `json:"finalize_unbonding"`
	} `json:"phase_txs"`
	Timing struct {
		StartHeight            int64 `json:"start_height"`
		EndHeight              int64 `json:"end_height"`
		HeightDelta            int64 `json:"height_delta"`
		DurationS              int64 `json:"duration_s"`
		ReleaseHeight          int64 `json:"release_height"`
		CooldownWaitedBlocks   int64 `json:"cooldown_waited_blocks"`
		CooldownStagnantRounds int64 `json:"cooldown_stagnant_rounds"`
	} `json:"timing"`
	Node struct {
		Height     string `json:"height"`
		CatchingUp string `json:"catching_up"`
	} `json:"node"`
	// Also check top-level fields for compatibility if they exist
	StartHeight int64 `json:"start_height"`
	EndHeight   int64 `json:"end_height"`
}

func main() {
	v2File := "../examples/lifecycle_summary_v2_ok.json"
	v3File := "../examples/lifecycle_summary_v3_ok.json"

	v2Bytes, err := os.ReadFile(v2File)
	if err != nil {
		panic(err)
	}
	v3Bytes, err := os.ReadFile(v3File)
	if err != nil {
		panic(err)
	}

	var v2 SummaryV2
	if err := json.Unmarshal(v2Bytes, &v2); err != nil {
		panic(err)
	}

	var v3 SummaryV3
	if err := json.Unmarshal(v3Bytes, &v3); err != nil {
		panic(err)
	}

	// Verify Core Fields
	if v2.Status != v3.Status {
		fmt.Printf("Mismatch Status: %s vs %s\n", v2.Status, v3.Status)
		os.Exit(1)
	}
	if v2.Worker != v3.Worker {
		fmt.Printf("Mismatch Worker: %s vs %s\n", v2.Worker, v3.Worker)
		os.Exit(1)
	}
	if v2.LastStep != v3.LastStep {
		fmt.Printf("Mismatch LastStep: %s vs %s\n", v2.LastStep, v3.LastStep)
		os.Exit(1)
	}

	// Verify Logic Mapping (V2 flat vs V3 nested)
	if v2.StartHeight != v3.Timing.StartHeight {
		fmt.Printf("Mismatch StartHeight: %d vs %d\n", v2.StartHeight, v3.Timing.StartHeight)
		os.Exit(1)
	}
	// Also check if V3 top level matches V3 nested (consistency check)
	if v3.StartHeight != 0 && v3.StartHeight != v3.Timing.StartHeight {
		fmt.Printf("V3 Internal Mismatch StartHeight: %d vs %d\n", v3.StartHeight, v3.Timing.StartHeight)
		os.Exit(1)
	}

	if v2.EndHeight != v3.Timing.EndHeight {
		fmt.Printf("Mismatch EndHeight: %d vs %d\n", v2.EndHeight, v3.Timing.EndHeight)
		os.Exit(1)
	}

	if v2.TxRegister != v3.PhaseTxs.Register {
		fmt.Printf("Mismatch TxRegister: %s vs %s\n", v2.TxRegister, v3.PhaseTxs.Register)
		os.Exit(1)
	}

	// Node info
	if v2.NodeHeight != v3.Node.Height {
		fmt.Printf("Mismatch NodeHeight: %s vs %s\n", v2.NodeHeight, v3.Node.Height)
		os.Exit(1)
	}
	if v2.CatchingUp != v3.Node.CatchingUp {
		fmt.Printf("Mismatch CatchingUp: %s vs %s\n", v2.CatchingUp, v3.Node.CatchingUp)
		os.Exit(1)
	}

	fmt.Println("SUCCESS: v2 and v3 fixtures are semantically consistent.")
}
