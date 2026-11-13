// Independent, non-activated full-width ASERT arithmetic oracle for PoN.
// This CLI imports no Rust/Python code and never constructs a valid block.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
)

var (
	one     = big.NewInt(1)
	radix   = big.NewInt(1 << 16)
	maxI128 = new(big.Int).Sub(new(big.Int).Lsh(new(big.Int).Set(one), 127), one)
	minI128 = new(big.Int).Neg(new(big.Int).Lsh(new(big.Int).Set(one), 127))
	maxU256 = new(big.Int).Sub(new(big.Int).Lsh(new(big.Int).Set(one), 256), one)
)

type Inputs struct {
	AnchorTarget     *big.Int
	PowLimit         *big.Int
	AnchorParentTime uint64
	ParentTime       uint64
	AnchorHeight     uint64
	CandidateHeight  uint64
	Spacing          uint64
	HalfLife         uint64
}

func withinI128(x *big.Int) bool { return x.Cmp(minI128) >= 0 && x.Cmp(maxI128) <= 0 }

// AsertTarget evaluates the aserti3-2d polynomial in 16-bit fixed-point
// units, deliberately without Bitcoin Cash nBits compact rounding. The
// candidate's context/anchor must be authenticated by a future independent
// consensus owner, never by this unsigned research CLI.
func AsertTarget(in Inputs) (*big.Int, error) {
	if in.AnchorTarget == nil || in.PowLimit == nil || in.AnchorTarget.Sign() <= 0 ||
		in.PowLimit.Sign() <= 0 || in.PowLimit.Cmp(maxU256) > 0 ||
		in.AnchorTarget.Cmp(in.PowLimit) > 0 || in.AnchorHeight == 0 ||
		in.CandidateHeight <= in.AnchorHeight || in.Spacing == 0 || in.HalfLife == 0 {
		return nil, errors.New("ASERT_RESEARCH_PARAMETERS")
	}
	// Evaluate all signed terms independently and check the native i128 domain
	// before multiplying by the fixed-point radix.
	ideal := new(big.Int).Mul(new(big.Int).SetUint64(in.CandidateHeight-in.AnchorHeight),
		new(big.Int).SetUint64(in.Spacing))
	if !withinI128(ideal) {
		return nil, errors.New("ASERT_RESEARCH_RANGE")
	}
	elapsed := new(big.Int).Sub(new(big.Int).SetUint64(in.ParentTime),
		new(big.Int).SetUint64(in.AnchorParentTime))
	deviation := new(big.Int).Sub(elapsed, ideal)
	if !withinI128(deviation) {
		return nil, errors.New("ASERT_RESEARCH_RANGE")
	}
	scaled := new(big.Int).Mul(deviation, radix)
	if !withinI128(scaled) {
		return nil, errors.New("ASERT_RESEARCH_RANGE")
	}
	exponent := new(big.Int).Quo(scaled, new(big.Int).SetUint64(in.HalfLife))
	shift, frac := new(big.Int), new(big.Int)
	shift.DivMod(exponent, radix, frac) // Euclidean: fractional part always 0..65535
	if shift.Cmp(big.NewInt(256)) >= 0 {
		return new(big.Int).Set(in.PowLimit), nil
	}
	if shift.Cmp(big.NewInt(-512)) <= 0 {
		return new(big.Int).Set(one), nil
	}
	f2 := new(big.Int).Mul(frac, frac)
	f3 := new(big.Int).Mul(f2, frac)
	a := new(big.Int).Mul(big.NewInt(195766423245049), frac)
	b := new(big.Int).Mul(big.NewInt(971821376), f2)
	c := new(big.Int).Mul(big.NewInt(5127), f3)
	poly := new(big.Int).Add(a, b)
	poly.Add(poly, c)
	poly.Add(poly, new(big.Int).Lsh(new(big.Int).Set(one), 47))
	factor := new(big.Int).Rsh(poly, 48)
	factor.Add(factor, radix)
	if factor.Cmp(radix) < 0 || factor.Cmp(new(big.Int).Lsh(new(big.Int).Set(one), 17)) > 0 {
		return nil, errors.New("ASERT_RESEARCH_FACTOR")
	}
	v := new(big.Int).Mul(in.AnchorTarget, factor)
	n := shift.Int64() // bounded by the two early-return guards above
	if n >= 0 {
		v.Lsh(v, uint(n))
	} else {
		v.Rsh(v, uint(-n))
	}
	v.Rsh(v, 16)
	if v.Sign() == 0 {
		v.Set(one)
	}
	if v.Cmp(in.PowLimit) > 0 {
		v.Set(in.PowLimit)
	}
	return v, nil
}

func fixedInputs() Inputs {
	return Inputs{
		AnchorTarget: new(big.Int).Lsh(new(big.Int).Set(one), 220),
		PowLimit:     new(big.Int).Sub(new(big.Int).Lsh(new(big.Int).Set(one), 240), one),
		AnchorHeight: 1, CandidateHeight: 2, Spacing: 10, HalfLife: 7200,
	}
}

func fixtureDigest() (string, error) {
	state := uint64(0x62b7f30ac9851d4e)
	next := func() uint64 {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		return state
	}
	hash := sha256.New()
	for i := uint64(0); i < 512; i++ {
		x := fixedInputs()
		x.CandidateHeight = 2 + next()%1000
		x.AnchorParentTime = 1000000 + next()%100000
		deviation := int64(next()%100000) - 50000
		x.ParentTime = uint64(int64(x.AnchorParentTime) + int64((x.CandidateHeight-1)*10) + deviation)
		if i%17 == 0 {
			x.ParentTime = ^uint64(0)
		}
		if i%19 == 0 {
			x.ParentTime = 0
		}
		x.HalfLife = [...]uint64{3600, 7200, 14400, 28800, 1}[i%5]
		value, err := AsertTarget(x)
		if err != nil {
			return "", fmt.Errorf("fixture %d: %w", i, err)
		}
		buf := value.FillBytes(make([]byte, 32))
		hash.Write(buf)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func decodeTarget(raw string) (*big.Int, error) {
	if len(raw) != 64 {
		return nil, errors.New("expected exact 64-character target hex")
	}
	bytes, err := hex.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(bytes), nil
}

func main() {
	fixture := flag.Bool("fixtures", false, "emit exact 512-case cross-language digest")
	anchorHex := flag.String("anchor", "0000000010000000000000000000000000000000000000000000000000000000", "256-bit anchored target hex")
	limitHex := flag.String("limit", "0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "256-bit pow limit hex")
	anchorTime := flag.Uint64("anchor-parent-time", 0, "authenticated anchor predecessor time")
	parentTime := flag.Uint64("parent-time", 10, "authenticated current predecessor time")
	anchorHeight := flag.Uint64("anchor-height", 1, "height of anchored block")
	height := flag.Uint64("height", 2, "candidate block height")
	spacing := flag.Uint64("spacing", 10, "target seconds per block")
	halfLife := flag.Uint64("half-life", 7200, "DAA half-life seconds")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}
	if *fixture {
		digest, err := fixtureDigest()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
			"schema": "pon-asert-third-oracle-v1", "sha256_512": digest,
			"cases": 512, "consensus_activation": false, "valid_w1_proofs": 0,
		})
		return
	}
	anchor, err := decodeTarget(*anchorHex)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	limit, err := decodeTarget(*limitHex)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	target, err := AsertTarget(Inputs{AnchorTarget: anchor, PowLimit: limit,
		AnchorParentTime: *anchorTime, ParentTime: *parentTime, AnchorHeight: *anchorHeight,
		CandidateHeight: *height, Spacing: *spacing, HalfLife: *halfLife})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Printf("%064x\n", target)
}
