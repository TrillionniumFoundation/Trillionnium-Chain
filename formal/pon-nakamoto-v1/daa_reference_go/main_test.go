package main

import (
	"math/big"
	"testing"
)

func TestIndependentSeededVectorsMatchFrozenPythonAndRust(t *testing.T) {
	got, err := fixtureDigest()
	if err != nil {
		t.Fatal(err)
	}
	const want = "6be87e237c37aec8c50af8d4eaf9e14a0ca60e7dc69f18143ede1ef70c420c97"
	if got != want {
		t.Fatalf("512-case SHA256: got %s want %s", got, want)
	}
}

func TestKnownFixedPointVectorsAndRefusals(t *testing.T) {
	// Independently implementable full-width PoN target vectors, not Bitcoin nBits.
	cases := []struct {
		parent uint64
		height uint64
		half   uint64
		want   string
	}{
		{10, 2, 7200, "0000000010000000000000000000000000000000000000000000000000000000"},
		{20, 2, 7200, "000000001003f000000000000000000000000000000000000000000000000000"},
		{0, 2, 7200, "000000000ffc1000000000000000000000000000000000000000000000000000"},
		{2000, 80, 7200, "0000000011fa7000000000000000000000000000000000000000000000000000"},
		{800, 80, 7200, "000000001003f000000000000000000000000000000000000000000000000000"},
	}
	for _, v := range cases {
		x := fixedInputs()
		x.ParentTime = v.parent
		x.CandidateHeight = v.height
		x.HalfLife = v.half
		got, err := AsertTarget(x)
		if err != nil {
			t.Fatal(err)
		}
		if s := got.Text(16); s != newTarget(t, v.want).Text(16) {
			t.Errorf("case %+v got %064x", v, got)
		}
	}
	bad := fixedInputs()
	bad.HalfLife = 0
	if _, err := AsertTarget(bad); err == nil {
		t.Fatal("accepted zero half-life")
	}
	bad = fixedInputs()
	bad.AnchorTarget = new(big.Int).Add(bad.PowLimit, one)
	if _, err := AsertTarget(bad); err == nil {
		t.Fatal("accepted target above pow limit")
	}
	bad = fixedInputs()
	bad.CandidateHeight = bad.AnchorHeight
	if _, err := AsertTarget(bad); err == nil {
		t.Fatal("accepted nonincreasing height")
	}
	bad = fixedInputs()
	bad.CandidateHeight = ^uint64(0)
	bad.Spacing = ^uint64(0)
	if _, err := AsertTarget(bad); err == nil {
		t.Fatal("accepted exponent ideal-span overflow")
	}
	bad = fixedInputs()
	bad.ParentTime = ^uint64(0)
	bad.HalfLife = 1
	if got, err := AsertTarget(bad); err != nil || got.Cmp(bad.PowLimit) != 0 {
		t.Fatalf("failed positive shift saturation got=%v err=%v", got, err)
	}
	bad = fixedInputs()
	bad.AnchorParentTime = ^uint64(0)
	bad.HalfLife = 1
	if got, err := AsertTarget(bad); err != nil || got.Cmp(one) != 0 {
		t.Fatalf("failed negative shift saturation got=%v err=%v", got, err)
	}
}

func newTarget(t *testing.T, hex string) *big.Int {
	t.Helper()
	x, err := decodeTarget(hex)
	if err != nil {
		t.Fatal(err)
	}
	return x
}
