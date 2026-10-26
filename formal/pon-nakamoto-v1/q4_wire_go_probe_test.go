package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T) Fixture {
	t.Helper()
	bytes, e := os.ReadFile("q4_signed_wire_vectors_v1.json")
	if e != nil {
		t.Fatal(e)
	}
	var f Fixture
	if e = json.Unmarshal(bytes, &f); e != nil {
		t.Fatal(e)
	}
	return f
}
func TestMultipleSignedHeightsAndRefusal(t *testing.T) {
	f := fixture(t)
	for _, h := range []uint64{850, 899, 900, 950, 999, 1000} {
		v, e := Verify(f, h)
		if e != nil || !v.ResearchOnly {
			t.Fatalf("height %d: %v", h, e)
		}
	}
	for _, h := range []uint64{849, 1001, 1100} {
		if _, e := Verify(f, h); e == nil {
			t.Errorf("height %d unexpectedly accepted", h)
		}
	}
}
func TestSourceAndRequesterSignatures(t *testing.T) {
	f := fixture(t)
	for _, index := range []int{1059, 1100, 1123, 1186} {
		altered := f
		arr := []byte(f.Signed)
		arr[index*2] ^= 1
		altered.Signed = string(arr)
		if _, e := Verify(altered, 900); e == nil {
			t.Errorf("mutated signed byte %d accepted", index)
		}
	}
}
func TestIdentityAndContext(t *testing.T) {
	f := fixture(t)
	mutations := []Fixture{}
	bad := f
	bad.Network = strings.Repeat("01", 32)
	mutations = append(mutations, bad)
	bad = f
	bad.OldID = strings.Repeat("00", 32)
	mutations = append(mutations, bad)
	bad = f
	bad.Source = f.Requester
	mutations = append(mutations, bad)
	for _, m := range mutations {
		if _, e := Verify(m, 900); e == nil {
			t.Error("foreign identity accepted")
		}
	}
}
