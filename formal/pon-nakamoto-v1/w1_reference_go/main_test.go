package main

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestIndependentMaintenanceTaskDigest(t *testing.T) {
	a := make([]byte, 4096*4)
	b := make([]byte, 4096*4)
	for i := 0; i < 4096; i++ {
		binary.LittleEndian.PutUint32(a[4*i:], uint32((13*i+17)%257))
		binary.LittleEndian.PutUint32(b[4*i:], uint32((29*i+31)%263))
	}
	got := H("task", a, b)
	if hex.EncodeToString(got[:]) != "c982eea0545c228d0bf48d6d06e623020b4031f2ba79da56cc6bdccde2c63496" {
		t.Fatal("material work TaskId differs from separate Python original")
	}
}
func TestStrictWorkPrechecksRejectMalformedUnconditionally(t *testing.T) {
	header := make([]byte, 318)
	proof := make([]byte, 49188)
	if _, _, e := ticketPrecheck(header, proof); e == nil || e.Error() != "VERSION" {
		t.Fatalf("wrong header version: %v", e)
	}
	if _, _, e := ticketPrecheck(header[:3], proof); e == nil || e.Error() != "LENGTH" {
		t.Fatalf("wrong header length: %v", e)
	}
	if _, _, e := ticketPrecheck(header, proof[:100]); e == nil || e.Error() != "LENGTH" {
		t.Fatalf("wrong proof length: %v", e)
	}
}
func TestIndependentRealFullTranscriptAndRefusal(t *testing.T) {
	report := os.Getenv("TRNM_W1_REAL_REPORT")
	dir := os.Getenv("TRNM_W1_REAL_ARTIFACT_DIR")
	if report == "" || dir == "" {
		t.Skip("requires bounded raw PNH1/PNW1 research artifact directory; not a default no-op success")
	}
	got, e := run(report, dir)
	if e != nil {
		t.Fatalf("readback failed: %v", e)
	}
	if got["full_w1_mathematical_proofs"] != 31 || got["false_trace_rejected"] != true || got["honest_heavier_by_work"] != true || got["native_Node_acceptance"] != false {
		t.Fatalf("untrusted result: %#v", got)
	}
	name := "13c4e595a1eef4a8e4eda7169e3452518dc6c701aa3e5a8ac6d89ceb2ef21071"
	header, e := loadExact(filepath.Join(dir, name+".pnh1"), headerBytes)
	if e != nil {
		t.Fatal(e)
	}
	proof, e := loadExact(filepath.Join(dir, name+".pnw1"), proofBytes)
	if e != nil {
		t.Fatal(e)
	}
	id, ticket, e := fullVerify(header, proof)
	if e != nil {
		t.Fatalf("original W1 full: %v", e)
	}
	if hex.EncodeToString(id[:]) != name || len(ticket) != 32 {
		t.Fatal("wrong verified block identity")
	}

	changed := append([]byte(nil), proof...)
	changed[len(changed)-1] ^= 1
	if _, _, e := fullVerify(header, changed); e == nil {
		t.Fatal("tampered full relation became valid")
	}
	changedHeader := append([]byte(nil), header...)
	changedHeader[278] ^= 1
	if _, _, e := fullVerify(changedHeader, proof); e == nil || e.Error() != "TASK" {
		t.Fatalf("mutated task verdict: %v", e)
	}

	temp := t.TempDir()
	if e := os.WriteFile(filepath.Join(temp, name+".pnh1"), header, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(temp, name+".pnw1"), changed, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := run(report, temp); e == nil {
		t.Fatal("mutated first packet accepted at report level")
	}
}
func TestStrictReadRejectsSizeAndPathAlias(t *testing.T) {
	tmp := t.TempDir()
	name := filepath.Join(tmp, "one")
	if e := os.WriteFile(name, make([]byte, 13), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := loadExact(name, 14); e == nil {
		t.Fatal("missing byte accepted")
	}
	if _, e := loadExact(name, 13); e != nil {
		t.Fatalf("regular exact-size file refused: %v", e)
	}
	alias := filepath.Join(tmp, "alias")
	if e := os.Symlink(name, alias); e == nil {
		if _, e := loadExact(alias, 13); e == nil {
			t.Fatal("symlink unexpectedly accepted")
		}
	}
}
