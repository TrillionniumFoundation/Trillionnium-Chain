package daaoracle

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"
)

const base = "0x10000000000000000000000000000000000000000000000000000000"          // 2^220
const capTarget = "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" // 2^240-1
func sample(before, parent, height uint64, halflife uint64) Input {
	return Input{base, before, parent, 1, height, 10, halflife, capTarget}
}
func TestFrozenNativeRustVectors(t *testing.T) {
	cases := []struct {
		in   Input
		want string
	}{
		{sample(0, 10, 2, 7200), "0000000010000000000000000000000000000000000000000000000000000000"},
		{sample(0, 20, 2, 7200), "000000001003f000000000000000000000000000000000000000000000000000"},
		{sample(0, 0, 2, 7200), "000000000ffc1000000000000000000000000000000000000000000000000000"},
		{sample(0, 2000, 80, 7200), "0000000011fa7000000000000000000000000000000000000000000000000000"},
		{sample(0, 800, 80, 7200), "000000001003f000000000000000000000000000000000000000000000000000"},
		{sample(2000, 1800, 100, 3600), "000000000cb95000000000000000000000000000000000000000000000000000"},
		{sample(0, 1<<20, 2, 3600), "0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{sample(1<<20, 0, 2, 3600), "0000000000000000000000000000000000000000000000000000000000000001"},
	}
	for i, tc := range cases {
		got, e := ASERT(tc.in)
		if e != nil {
			t.Fatalf("case %d: %v", i, e)
		}
		if EncodeHex32(got) != tc.want {
			t.Errorf("case %d got %s expected %s", i, EncodeHex32(got), tc.want)
		}
	}
}
func TestRust512VectorDigest(t *testing.T) {
	state := uint64(0x62b7f30ac9851d4e)
	next := func() uint64 { state ^= state << 13; state ^= state >> 7; state ^= state << 17; return state }
	hh := sha256.New()
	horizons := []uint64{3600, 7200, 14400, 28800, 1}
	for i := 0; i < 512; i++ {
		h := uint64(2) + next()%1000
		before := uint64(1000000) + next()%100000
		d := int64(next()%100000) - 50000
		// Match the Rust cast via wrapping i64; this case never underflows.
		parent := uint64(int64(before) + int64((h-1)*10) + d)
		if i%17 == 0 {
			parent = ^uint64(0)
		}
		if i%19 == 0 {
			parent = 0
		}
		got, e := ASERT(sample(before, parent, h, horizons[i%5]))
		if e != nil {
			t.Fatalf("%d %v", i, e)
		}
		b := got.FillBytes(make([]byte, 32))
		hh.Write(b)
	}
	if got := fmt.Sprintf("%x", hh.Sum(nil)); got != "6be87e237c37aec8c50af8d4eaf9e14a0ca60e7dc69f18143ede1ef70c420c97" {
		t.Fatalf("digest=%s", got)
	}
}
func TestRejectionsAndLegacy(t *testing.T) {
	bad := sample(0, 10, 2, 0)
	if _, e := ASERT(bad); e != ErrParameters {
		t.Fatalf("expected parameters: %v", e)
	}
	bad = sample(^uint64(0), 0, ^uint64(0), 1)
	bad.Spacing = ^uint64(0)
	if _, e := ASERT(bad); e != ErrRange {
		t.Fatalf("expected range: %v", e)
	}
	for _, s := range []string{"0", "012", "+1", "0Xff", "0x0", "-1", "1e3", "0x", "0xgg", "1 ", ""} {
		if _, e := ParseTarget(s); e == nil {
			t.Errorf("accepted noncanonical/invalid %q", s)
		}
	}
	tgt, _ := ParseTarget(base)
	limit, _ := ParseTarget(capTarget)
	got, e := LegacyRetarget(tgt, 100, 700, 16, 10, limit)
	if e != nil {
		t.Fatal(e)
	}
	expected := new(big.Int).Mul(tgt, big.NewInt(4))
	if got.Cmp(expected) != 0 {
		t.Fatalf("legacy got %s", got)
	}
	if m, e := MTP([]uint64{100, 102, 90, 104, 101}); e != nil || m != 101 {
		t.Fatalf("mtp %v %v", m, e)
	}
}
