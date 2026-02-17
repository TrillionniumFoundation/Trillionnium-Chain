package tools

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type lifecycleContract struct {
	FlatRequired []string            `json:"flat_required"`
	V3Nested     map[string][]string `json:"v3_nested"`
}

func TestLifecycleSummaryContractAndFixtures(t *testing.T) {
	root := mustRepoRoot(t)
	contract := mustLoadContract(t, filepath.Join(root, "tools", "lifecycle_summary_schema_contract.json"))
	mustMatchMarkdownTokens(t, filepath.Join(root, "tools", "LIFECYCLE_SUMMARY_SCHEMA_CONTRACT.md"), contract)
	mustValidateFixtures(t, filepath.Join(root, "tools", "examples"), contract)
}

func mustRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if filepath.Base(wd) == "tools" {
		return filepath.Dir(wd)
	}
	return wd
}

func mustLoadContract(t *testing.T, path string) lifecycleContract {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read contract: %v", err)
	}
	var c lifecycleContract
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("decode contract: %v", err)
	}
	if len(c.FlatRequired) == 0 || len(c.V3Nested) == 0 {
		t.Fatalf("contract cannot be empty")
	}
	return c
}

func mustMatchMarkdownTokens(t *testing.T, markdownPath string, contract lifecycleContract) {
	t.Helper()
	b, err := os.ReadFile(markdownPath)
	if err != nil {
		t.Fatalf("read markdown contract: %v", err)
	}
	lines := strings.Split(string(b), "\n")

	v2Doc := extractBacktickList(lines, "Required top-level fields (same as v1):", "## v3 Contract")
	v2Expected := append([]string(nil), contract.FlatRequired...)
	slices.Sort(v2Doc)
	slices.Sort(v2Expected)
	if !slices.Equal(v2Doc, v2Expected) {
		t.Fatalf("v2 markdown/json drift: doc=%v json=%v", v2Doc, v2Expected)
	}

	v3Doc := extractBacktickList(lines, "## v3 Contract", "### Status Semantics")
	var v3Expected []string
	for k, fields := range contract.V3Nested {
		v3Expected = append(v3Expected, k)
		v3Expected = append(v3Expected, fields...)
	}
	slices.Sort(v3Doc)
	slices.Sort(v3Expected)
	if !slices.Equal(v3Doc, v3Expected) {
		t.Fatalf("v3 markdown/json drift: doc=%v json=%v", v3Doc, v3Expected)
	}
}

func extractBacktickList(lines []string, start, end string) []string {
	inBlock := false
	set := map[string]struct{}{}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == start {
			inBlock = true
			continue
		}
		if trimmed == end {
			inBlock = false
		}
		if !inBlock || !strings.HasPrefix(trimmed, "-") {
			continue
		}
		for _, token := range tokensInBackticks(line) {
			set[token] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for token := range set {
		out = append(out, token)
	}
	return out
}

func tokensInBackticks(s string) []string {
	parts := strings.Split(s, "`")
	out := make([]string, 0, len(parts)/2)
	for i := 1; i < len(parts); i += 2 {
		if parts[i] != "" {
			out = append(out, parts[i])
		}
	}
	return out
}

func mustValidateFixtures(t *testing.T, examplesDir string, contract lifecycleContract) {
	t.Helper()
	v1 := mustLoadJSONMap(t, filepath.Join(examplesDir, "lifecycle_summary_v1_failed.json"))
	v2 := mustLoadJSONMap(t, filepath.Join(examplesDir, "lifecycle_summary_v2_ok.json"))
	v3 := mustLoadJSONMap(t, filepath.Join(examplesDir, "lifecycle_summary_v3_ok.json"))

	assertSchemaVersion(t, v1, 1)
	assertSchemaVersion(t, v2, 2)
	assertSchemaVersion(t, v3, 3)
	if v1["status"] != "failed" {
		t.Fatalf("v1 status must be failed")
	}
	if !strings.HasPrefix(asString(v1["reason"]), "finalize-unbonding broadcast failed") {
		t.Fatalf("v1 reason prefix mismatch")
	}
	if v2["status"] != "ok" || v3["status"] != "ok" {
		t.Fatalf("v2/v3 status should be ok")
	}

	assertExactKeys(t, v2, contract.FlatRequired)

	v3Required := append(append([]string(nil), contract.FlatRequired...), "phase_txs", "timing", "node")
	assertExactKeys(t, v3, v3Required)

	phase := asMap(t, v3["phase_txs"], "phase_txs")
	timing := asMap(t, v3["timing"], "timing")
	node := asMap(t, v3["node"], "node")
	assertExactKeys(t, phase, contract.V3Nested["phase_txs"])
	assertExactKeys(t, timing, contract.V3Nested["timing"])
	assertExactKeys(t, node, contract.V3Nested["node"])

	assertSame(t, phase["register"], v3["tx_register"], "phase_txs.register")
	assertSame(t, phase["request_unbonding"], v3["tx_request_unbonding"], "phase_txs.request_unbonding")
	assertSame(t, phase["finalize_unbonding"], v3["tx_finalize_unbonding"], "phase_txs.finalize_unbonding")
	assertSame(t, timing["start_height"], v3["start_height"], "timing.start_height")
	assertSame(t, timing["end_height"], v3["end_height"], "timing.end_height")
	assertSame(t, timing["height_delta"], v3["height_delta"], "timing.height_delta")
	assertSame(t, timing["duration_s"], v3["duration_s"], "timing.duration_s")
	assertSame(t, timing["release_height"], v3["release_height"], "timing.release_height")
	assertSame(t, timing["cooldown_waited_blocks"], v3["cooldown_waited_blocks"], "timing.cooldown_waited_blocks")
	assertSame(t, timing["cooldown_stagnant_rounds"], v3["cooldown_stagnant_rounds"], "timing.cooldown_stagnant_rounds")
	assertSame(t, node["height"], v3["node_height"], "node.height")
	if asString(node["catching_up"]) != asString(v3["catching_up"]) {
		t.Fatalf("node.catching_up mismatch")
	}
}

func mustLoadJSONMap(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode fixture %s: %v", path, err)
	}
	return out
}

func assertSchemaVersion(t *testing.T, m map[string]any, expected int) {
	t.Helper()
	if int(m["schema_version"].(float64)) != expected {
		t.Fatalf("schema_version mismatch, got=%v want=%d", m["schema_version"], expected)
	}
}

func assertExactKeys(t *testing.T, m map[string]any, expected []string) {
	t.Helper()
	actual := make([]string, 0, len(m))
	for k := range m {
		actual = append(actual, k)
	}
	slices.Sort(actual)
	exp := append([]string(nil), expected...)
	slices.Sort(exp)
	if !slices.Equal(actual, exp) {
		t.Fatalf("keys mismatch\nactual=%v\nexpected=%v", actual, exp)
	}
}

func asMap(t *testing.T, v any, label string) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%s must be object", label)
	}
	return m
}

func asString(v any) string {
	switch tv := v.(type) {
	case string:
		return tv
	case bool:
		if tv {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprint(tv)
	}
}

func assertSame(t *testing.T, got any, want any, label string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s mismatch: got=%v want=%v", label, got, want)
	}
}
