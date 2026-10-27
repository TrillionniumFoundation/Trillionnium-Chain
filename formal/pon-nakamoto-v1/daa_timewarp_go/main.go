// Standalone *research-only* independent replay of a Python DAA timestamp screen.
// Does not validate W1, a real blockchain, lease signatures or model utility.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"sort"
)

var (
	two256   = new(big.Int).Lsh(big.NewInt(1), 256)
	one      = big.NewInt(1)
	max256   = new(big.Int).Sub(new(big.Int).Set(two256), one)
	powTwo47 = new(big.Int).Lsh(big.NewInt(1), 47)
	div48    = new(big.Int).Lsh(big.NewInt(1), 48)
	div16    = new(big.Int).Lsh(big.NewInt(1), 16)
)

func fail(f string, a ...any) { fmt.Fprintf(os.Stderr, "DAA_GO_REJECT "+f+"\n", a...); os.Exit(2) }
func parseU(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok || v.Sign() <= 0 || v.Cmp(max256) > 0 {
		fail("bad 256-bit value %q", s)
	}
	return v
}
func minmax(v, low, high *big.Int) *big.Int {
	if v.Cmp(low) < 0 {
		return new(big.Int).Set(low)
	}
	if v.Cmp(high) > 0 {
		return new(big.Int).Set(high)
	}
	return new(big.Int).Set(v)
}
func median(vals []uint64) uint64 {
	if len(vals) < 1 || len(vals) > 11 {
		fail("missing/oversized mtp")
	}
	sorted := append([]uint64(nil), vals...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[len(sorted)/2]
}
func historyMTP(times []uint64, height int) uint64 {
	from := height - 11
	if from < 0 {
		from = 0
	}
	return median(times[from:height])
}
func legacy(parent *big.Int, times []uint64, height int, spacing uint64, pow *big.Int) *big.Int {
	if height%16 != 0 {
		return new(big.Int).Set(parent)
	}
	desired := uint64(15) * spacing
	var observed uint64 = 1
	if times[height-1] > times[height-16] {
		observed = times[height-1] - times[height-16]
	}
	lower := (desired + 3) / 4
	upper := desired * 4
	if observed < lower {
		observed = lower
	}
	if observed > upper {
		observed = upper
	}
	value := new(big.Int).Mul(parent, new(big.Int).SetUint64(observed))
	value.Quo(value, new(big.Int).SetUint64(desired))
	return minmax(value, one, pow)
}
func asert(anchor *big.Int, anchorParentTime, observed uint64, anchorHeight, height int,
	spacing, halfLife uint64, pow *big.Int) *big.Int {
	if height <= anchorHeight || halfLife == 0 {
		fail("bad ASERT parameters")
	}
	delta := new(big.Int).SetUint64(observed)
	delta.Sub(delta, new(big.Int).SetUint64(anchorParentTime))
	delta.Sub(delta, new(big.Int).Mul(big.NewInt(int64(height-anchorHeight)), new(big.Int).SetUint64(spacing)))
	scaled := new(big.Int).Lsh(delta, 16)
	i128Max := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 127), one)
	i128Min := new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 127))
	if scaled.Cmp(i128Max) > 0 || scaled.Cmp(i128Min) < 0 {
		fail("exponent exceeds i128")
	}
	expo := new(big.Int).Quo(scaled, new(big.Int).SetUint64(halfLife)) // toward zero
	shifts := new(big.Int)
	fractional := new(big.Int)
	shifts.DivMod(expo, div16, fractional) // floor + positive remainder
	if shifts.Cmp(big.NewInt(256)) >= 0 {
		return new(big.Int).Set(pow)
	}
	if shifts.Cmp(big.NewInt(-512)) <= 0 {
		return big.NewInt(1)
	}
	f2 := new(big.Int).Mul(fractional, fractional)
	f3 := new(big.Int).Mul(f2, fractional)
	poly := new(big.Int).Mul(big.NewInt(195766423245049), fractional)
	poly.Add(poly, new(big.Int).Mul(big.NewInt(971821376), f2))
	poly.Add(poly, new(big.Int).Mul(big.NewInt(5127), f3))
	poly.Add(poly, powTwo47)
	poly.Quo(poly, div48)
	poly.Add(poly, div16)
	value := new(big.Int).Mul(anchor, poly)
	if shifts.Sign() >= 0 {
		value.Lsh(value, uint(shifts.Int64()))
	} else {
		negative := new(big.Int).Neg(shifts)
		value.Rsh(value, uint(negative.Int64()))
	}
	value.Rsh(value, 16)
	return minmax(value, one, pow)
}
func work(target *big.Int) *big.Int {
	denominator := new(big.Int).Add(target, one)
	return new(big.Int).Quo(two256, denominator)
}

type Case struct {
	Schema               string   `json:"schema"`
	Algorithm            string   `json:"algorithm"`
	Blocks               int      `json:"blocks"`
	BeamWidth            int      `json:"beam_width"`
	Spacing              int      `json:"spacing"`
	FutureSkew           int      `json:"future_skew"`
	HalfLife             int      `json:"half_life"`
	InitialTarget        string   `json:"initial_target"`
	PowLimit             string   `json:"pow_limit"`
	TimeStamps           []uint64 `json:"time_stamps"`
	Targets              []string `json:"target_values"`
	HonestTarget         string   `json:"honest_final_target"`
	HonestWork           string   `json:"honest_chainwork"`
	SearchedWork         string   `json:"searched_chainwork"`
	FullW1               int      `json:"full_w1_proofs"`
	IndependentOperators int      `json:"independent_operators"`
	CaseHash             string   `json:"case_sha256"`
	EvaluatedCandidates  int      `json:"evaluated_legal_candidates"`
	PrunedCandidates     int      `json:"pruned_candidates"`
	ChosenEdges          []string `json:"chosen_edges"`
	Numerator            string   `json:"target_multiplier_numerator"`
	Denominator          string   `json:"target_multiplier_denominator"`
	Status               string   `json:"status"`
}
type Report struct {
	Schema               string            `json:"schema"`
	Cases                []json.RawMessage `json:"cases"`
	ActualW1             bool              `json:"actual_W1"`
	ProductionAcceptance bool              `json:"production_acceptance"`
}

func verifyCase(raw json.RawMessage) string {
	var c Case
	caseDecoder := json.NewDecoder(bytes.NewReader(raw))
	caseDecoder.DisallowUnknownFields()
	if err := caseDecoder.Decode(&c); err != nil {
		fail("decode case: %v", err)
	}
	if c.Schema != "pon-daa-timewarp-beam-research-v1" ||
		(c.Algorithm != "legacy16" && c.Algorithm != "asert_raw" && c.Algorithm != "asert_mtp11") ||
		c.Blocks < 16 || c.Blocks > 256 || c.Spacing < 1 || c.Spacing > 3600 ||
		c.HalfLife < 1 || c.HalfLife > 86400 || c.FutureSkew < 0 || c.FutureSkew > 3600 ||
		c.BeamWidth < 1 || c.BeamWidth > 256 || c.FullW1 != 0 || c.IndependentOperators != 0 ||
		len(c.TimeStamps) != c.Blocks+1 || len(c.Targets) != c.Blocks+1 || c.TimeStamps[0] != 0 || c.EvaluatedCandidates < c.Blocks ||
		c.PrunedCandidates < 0 || len(c.ChosenEdges) != c.Blocks ||
		c.Status != "hypothetical-time-valid-only-no-mined-blocks" {
		fail("invalid research scope or limits: %s", c.Algorithm)
	}
	anchor := parseU(c.InitialTarget)
	pow := parseU(c.PowLimit)
	if anchor.Cmp(pow) > 0 || parseU(c.Targets[0]).Cmp(anchor) != 0 ||
		parseU(c.Denominator).Cmp(anchor) != 0 ||
		parseU(c.Numerator).Cmp(parseU(c.Targets[c.Blocks])) != 0 {
		fail("bad genesis target")
	}
	cumulative := new(big.Int)
	honestTarget := new(big.Int).Set(anchor)
	honestWork := new(big.Int)
	for h := 1; h <= c.Blocks; h++ {
		observedMTP := historyMTP(c.TimeStamps, h)
		wall := uint64(h * c.Spacing)
		if c.TimeStamps[h] <= observedMTP || c.TimeStamps[h] > wall+uint64(c.FutureSkew) {
			fail("illegal timestamp algorithm=%s height=%d", c.Algorithm, h)
		}
		parent := parseU(c.Targets[h-1])
		expected := new(big.Int).Set(parent)
		switch c.Algorithm {
		case "legacy16":
			expected = legacy(parent, c.TimeStamps, h, uint64(c.Spacing), pow)
		case "asert_raw", "asert_mtp11":
			if h > 1 {
				t := c.TimeStamps[h-1]
				if c.Algorithm == "asert_mtp11" {
					t = observedMTP
				}
				expected = asert(anchor, 0, t, 1, h, uint64(c.Spacing), uint64(c.HalfLife), pow)
			}
		}
		got := parseU(c.Targets[h])
		if expected.Cmp(got) != 0 {
			fail("target disagreement algo=%s height=%d expected=%s got=%s", c.Algorithm, h, expected, got)
		}
		cumulative.Add(cumulative, work(got))
		honestHistory := make([]uint64, h)
		for j := 1; j < h; j++ {
			honestHistory[j] = uint64(j * c.Spacing)
		}
		switch c.Algorithm {
		case "legacy16":
			honestTarget = legacy(honestTarget, honestHistory, h, uint64(c.Spacing), pow)
		case "asert_raw", "asert_mtp11":
			if h > 1 {
				honestTime := honestHistory[h-1]
				if c.Algorithm == "asert_mtp11" {
					honestTime = historyMTP(honestHistory, h)
				}
				honestTarget = asert(anchor, 0, honestTime, 1, h, uint64(c.Spacing), uint64(c.HalfLife), pow)
			}
		}
		honestWork.Add(honestWork, work(honestTarget))
	}
	if cumulative.Cmp(parseU(c.SearchedWork)) != 0 {
		fail("chainwork mismatch: %s", c.Algorithm)
	}
	if parseU(c.HonestTarget).Cmp(honestTarget) != 0 || parseU(c.HonestWork).Cmp(honestWork) != 0 {
		fail("invalid honest comparison")
	}
	var generic map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&generic); err != nil {
		fail("canonical case JSON: %v", err)
	}
	delete(generic, "case_sha256")
	sorted, err := json.Marshal(generic)
	if err != nil {
		fail("canonical JSON encode: %v", err)
	}
	actual := sha256.Sum256(sorted)
	if c.CaseHash != hex.EncodeToString(actual[:]) {
		fail("case SHA mismatch: %s", c.Algorithm)
	}
	return fmt.Sprintf("%s:%d_headers:%s", c.Algorithm, c.Blocks, c.CaseHash)
}

func main() {
	if len(os.Args) != 2 {
		fail("usage: daa_timewarp_verify research.json")
	}
	contents, err := os.ReadFile(os.Args[1])
	if err != nil {
		fail("read: %v", err)
	}
	if len(contents) > 2_000_000 {
		fail("report too large")
	}
	var r Report
	if err := json.Unmarshal(contents, &r); err != nil {
		fail("JSON: %v", err)
	}
	if r.Schema != "pon-daa-timewarp-screen-v1" || r.ActualW1 || r.ProductionAcceptance || len(r.Cases) != 3 {
		fail("scope/research cases mismatch")
	}
	seen := map[string]bool{}
	for _, raw := range r.Cases {
		var a struct {
			Algorithm string `json:"algorithm"`
		}
		if err := json.Unmarshal(raw, &a); err != nil {
			fail("algorithm: %v", err)
		}
		if seen[a.Algorithm] {
			fail("duplicate algorithm")
		}
		seen[a.Algorithm] = true
		fmt.Println("RESEARCH_REPLAY_OK", verifyCase(raw))
	}
	for _, a := range []string{"legacy16", "asert_raw", "asert_mtp11"} {
		if !seen[a] {
			fail("missing %s", a)
		}
	}
}
