package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
)

type SummaryV2 struct {
	SchemaVersion int    `json:"schema_version"`
	Status        string `json:"status"`
	Worker        string `json:"worker"`
	LastStep      string `json:"last_step"`
	StartHeight   int64  `json:"start_height"`
	EndHeight     int64  `json:"end_height"`
}

type SummaryV3 struct {
	SchemaVersion int    `json:"schema_version"`
	Status        string `json:"status"`
	Worker        string `json:"worker"`
	LastStep      string `json:"last_step"`
	StartHeight   int64  `json:"start_height"`
	EndHeight     int64  `json:"end_height"`
	Timing        struct {
		StartHeight int64 `json:"start_height"`
		EndHeight   int64 `json:"end_height"`
	} `json:"timing"`
}

func main() {
	v2Path := "chain/tools/examples/lifecycle_summary_v2_ok.json"
	v3Path := "chain/tools/examples/lifecycle_summary_v3_ok.json"

	v2Data, err := os.ReadFile(v2Path)
	if err != nil {
		fmt.Printf("Error reading v2: %v\n", err)
		os.Exit(1)
	}

	v3Data, err := os.ReadFile(v3Path)
	if err != nil {
		fmt.Printf("Error reading v3: %v\n", err)
		os.Exit(1)
	}

	var v2 map[string]interface{}
	if err := json.Unmarshal(v2Data, &v2); err != nil {
		fmt.Printf("Error parsing v2: %v\n", err)
		os.Exit(1)
	}

	var v3 map[string]interface{}
	if err := json.Unmarshal(v3Data, &v3); err != nil {
		fmt.Printf("Error parsing v3: %v\n", err)
		os.Exit(1)
	}

	// Fields to compare strictly
	commonFields := []string{
		"status", "worker", "last_step", "last_tx",
		"start_height", "end_height", "height_delta", "duration_s",
		"release_height", "cooldown_waited_blocks", "cooldown_stagnant_rounds",
		// node_height and catching_up are strings in JSON
		"node_height", "catching_up",
	}

	mismatches := 0
	for _, field := range commonFields {
		val2, ok2 := v2[field]
		val3, ok3 := v3[field]

		if !ok2 {
			fmt.Printf("Field %s missing in v2\n", field)
			mismatches++
			continue
		}
		if !ok3 {
			// In v3, some fields might be nested, but the root level copy is expected by the prompt ("although structure different... core business fields values are same").
			// Let's check if the prompt implied checking nested vs flat or flat vs flat across versions.
			// "lifecycle_summary_v2_ok.json and v3_ok.json... core business fields values are identical"
			// The v3 file I read DOES have them at root too.
			fmt.Printf("Field %s missing in v3 root\n", field)
			mismatches++
			continue
		}

		if !reflect.DeepEqual(val2, val3) {
			fmt.Printf("Mismatch on %s: v2=%v, v3=%v\n", field, val2, val3)
			mismatches++
		}
	}

	// Also verify v3 internal consistency (root vs nested)
	// timing: start_height, end_height, etc.
	v3Timing, ok := v3["timing"].(map[string]interface{})
	if ok {
		timingFields := []string{"start_height", "end_height", "height_delta", "duration_s", "release_height", "cooldown_waited_blocks", "cooldown_stagnant_rounds"}
		for _, f := range timingFields {
			if rootVal, exists := v3[f]; exists {
				if nestedVal, nExists := v3Timing[f]; nExists {
					if !reflect.DeepEqual(rootVal, nestedVal) {
						fmt.Printf("v3 Internal Mismatch on timing.%s: root=%v, nested=%v\n", f, rootVal, nestedVal)
						mismatches++
					}
				}
			}
		}
	}

	if mismatches > 0 {
		fmt.Printf("Found %d mismatches\n", mismatches)
		os.Exit(1)
	}

	fmt.Println("Schema semantic consistency check passed!")
}
