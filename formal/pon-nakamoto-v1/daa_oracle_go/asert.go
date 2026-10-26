// Package daaoracle is an independent, non-activated ASERT arithmetic oracle.
// It is not a miner, work-hardness certificate, consensus module or deployment API.
// Calculations intentionally use Go math/big rather than Rust's eight-limb Work.
package daaoracle

import (
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

const Radix int64 = 65536

var canonicalTarget = regexp.MustCompile(`^(0x[0-9a-fA-F]+|[1-9][0-9]*|0)$`)

var (
	maxI128  = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 127), big.NewInt(1))
	minI128  = new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 127))
	maxU256  = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	bound512 = new(big.Int).Lsh(big.NewInt(1), 512)
)

var ErrParameters = errors.New("ASERT_RESEARCH_PARAMETERS")
var ErrRange = errors.New("ASERT_RESEARCH_RANGE")
var ErrTarget = errors.New("ASERT_RESEARCH_TARGET")

// Target strings are exact unsigned 256-bit integers. Accept decimal or 0x hex.
func ParseTarget(s string) (*big.Int, error) {
	if !canonicalTarget.MatchString(s) {
		return nil, ErrTarget
	}
	base := 10
	digits := s
	if strings.HasPrefix(s, "0x") {
		base = 16
		digits = s[2:]
	}
	value, ok := new(big.Int).SetString(digits, base)
	if !ok || value.Sign() <= 0 || value.Cmp(maxU256) > 0 {
		return nil, ErrTarget
	}
	return value, nil
}

// Input names the first anchored block and the raw- or MTP-derived parent time.
// The caller supplies authenticated ancestry; this function does not access it.
type Input struct {
	AnchorTarget         string `json:"anchor_target"`
	AnchorParentTime     uint64 `json:"anchor_parent_time"`
	EvaluationParentTime uint64 `json:"evaluation_parent_time"`
	AnchorHeight         uint64 `json:"anchor_height"`
	CandidateHeight      uint64 `json:"candidate_height"`
	Spacing              uint64 `json:"spacing"`
	HalfLife             uint64 `json:"half_life"`
	PowLimit             string `json:"pow_limit"`
}

func exactI128(x *big.Int) bool { return x.Cmp(minI128) >= 0 && x.Cmp(maxI128) <= 0 }
func u64(x uint64) *big.Int     { return new(big.Int).SetUint64(x) }

// ASERT returns an exact PoN u256 target. No Bitcoin compact-nBits rounding.
// It uses the aserti3-2d polynomial with truncation toward zero and Euclidean
// quotient/remainder for negative fixed-point exponents, matching the reviewed
// non-activated Rust candidate without calling or trusting that implementation.
func ASERT(in Input) (*big.Int, error) {
	anchor, e := ParseTarget(in.AnchorTarget)
	if e != nil {
		return nil, e
	}
	limit, e := ParseTarget(in.PowLimit)
	if e != nil {
		return nil, e
	}
	if anchor.Cmp(limit) > 0 || in.AnchorHeight == 0 || in.CandidateHeight <= in.AnchorHeight ||
		in.Spacing == 0 || in.HalfLife == 0 {
		return nil, ErrParameters
	}
	blocks := new(big.Int).SetUint64(in.CandidateHeight - in.AnchorHeight)
	ideal := new(big.Int).Mul(blocks, u64(in.Spacing))
	if !exactI128(ideal) {
		return nil, ErrRange
	}
	deviation := new(big.Int).Sub(u64(in.EvaluationParentTime), u64(in.AnchorParentTime))
	deviation.Sub(deviation, ideal)
	if !exactI128(deviation) {
		return nil, ErrRange
	}
	scaled := new(big.Int).Mul(deviation, big.NewInt(Radix))
	if !exactI128(scaled) {
		return nil, ErrRange
	}
	exponent := new(big.Int).Quo(scaled, u64(in.HalfLife))
	// Euclidean division: fraction is in [0,65535] even for negative exponent.
	shifts, frac := new(big.Int).DivMod(exponent, big.NewInt(Radix), new(big.Int))
	if shifts.Cmp(big.NewInt(256)) >= 0 {
		return limit, nil
	}
	if shifts.Cmp(big.NewInt(-512)) <= 0 {
		return big.NewInt(1), nil
	}
	f := new(big.Int).Set(frac)
	f2 := new(big.Int).Mul(f, f)
	f3 := new(big.Int).Mul(f2, f)
	polynomial := new(big.Int).Mul(big.NewInt(195766423245049), f)
	polynomial.Add(polynomial, new(big.Int).Mul(big.NewInt(971821376), f2))
	polynomial.Add(polynomial, new(big.Int).Mul(big.NewInt(5127), f3))
	polynomial.Add(polynomial, new(big.Int).Lsh(big.NewInt(1), 47))
	polynomial.Rsh(polynomial, 48)
	polynomial.Add(polynomial, big.NewInt(Radix))
	if polynomial.Cmp(big.NewInt(Radix)) < 0 || polynomial.Cmp(big.NewInt(2*Radix)) > 0 {
		return nil, fmt.Errorf("ASERT_RESEARCH_FACTOR")
	}
	value := new(big.Int).Mul(anchor, polynomial)
	// Research Rust works in 512 bits and saturates to PowLimit on overflow.
	if shifts.Sign() >= 0 {
		value.Lsh(value, uint(shifts.Uint64()))
		if value.Cmp(bound512) >= 0 {
			return limit, nil
		}
	} else {
		value.Rsh(value, uint(new(big.Int).Neg(shifts).Uint64()))
	}
	value.Rsh(value, 16)
	if value.Sign() == 0 {
		return big.NewInt(1), nil
	}
	if value.Cmp(limit) > 0 {
		return limit, nil
	}
	return value, nil
}

func EncodeHex32(x *big.Int) string { return fmt.Sprintf("%064x", x) }

// MTP returns the median of the nearest 1..11 branch timestamps, parent first.
// Passing a peer-selected or unverified time is a caller error.
func MTP(times []uint64) (uint64, error) {
	if len(times) == 0 {
		return 0, errors.New("ASERT_ANCESTRY_EMPTY")
	}
	if len(times) > 11 {
		times = times[:11]
	}
	copyTimes := append([]uint64(nil), times...)
	for i := 1; i < len(copyTimes); i++ {
		v := copyTimes[i]
		j := i - 1
		for j >= 0 && copyTimes[j] > v {
			copyTimes[j+1] = copyTimes[j]
			j--
		}
		copyTimes[j+1] = v
	}
	return copyTimes[len(copyTimes)/2], nil
}

// LegacyRetarget independently captures the existing 16-block boundary rule.
// There is no alternative activation or change to stored chain parameters.
func LegacyRetarget(parent *big.Int, first, last, interval, spacing uint64, limit *big.Int) (*big.Int, error) {
	if parent == nil || limit == nil || parent.Sign() <= 0 || parent.Cmp(limit) > 0 || interval < 16 || spacing == 0 {
		return nil, ErrParameters
	}
	desired := new(big.Int).Mul(u64(interval-1), u64(spacing))
	maxObserved := new(big.Int).Mul(desired, big.NewInt(4))
	if maxObserved.BitLen() > 64 {
		return nil, ErrRange
	}
	observed := uint64(1)
	if last >= first && last-first > 0 {
		observed = last - first
	}
	lower := new(big.Int).Add(desired, big.NewInt(3))
	lower.Div(lower, big.NewInt(4))
	span := u64(observed)
	if span.Cmp(lower) < 0 {
		span = lower
	}
	if span.Cmp(maxObserved) > 0 {
		span = maxObserved
	}
	newTarget := new(big.Int).Mul(parent, span)
	newTarget.Quo(newTarget, desired)
	if newTarget.Sign() == 0 {
		return big.NewInt(1), nil
	}
	if newTarget.Cmp(limit) > 0 {
		return new(big.Int).Set(limit), nil
	}
	return newTarget, nil
}
