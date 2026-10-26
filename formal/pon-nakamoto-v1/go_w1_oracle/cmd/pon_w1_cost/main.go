// pon_w1_cost: Go-only same-statement cost evidence, not public admission.
// Linux process CPU includes all Go threads/GC. Cookie IDs are synthetic,
// not signed by a V3 server. This tool has no consensus/VerifiedWork authority.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"
	w1 "trillionnium/pon-w1-research-oracle"
)

func cpu() (int64, bool) {
	var r syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &r) != nil {
		return 0, false
	}
	v := (r.Utime.Sec+r.Stime.Sec)*1000000000 + (r.Utime.Usec+r.Stime.Usec)*1000
	return v, v >= 0
}
func start() (time.Time, int64, bool) { c, ok := cpu(); return time.Now(), c, ok }
func elapsed(t time.Time, c int64, ok bool) map[string]any {
	e, valid := cpu()
	var delta any
	if ok && valid && e >= c {
		delta = e - c
	}
	return map[string]any{"wall_ns": time.Since(t).Nanoseconds(), "process_cpu_ns": delta}
}
func words(a []uint32) []byte {
	o := make([]byte, len(a)*4)
	for i, v := range a {
		binary.LittleEndian.PutUint32(o[i*4:], v)
	}
	return o
}
func hexHash(b []byte) string               { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func qualified(value, target [32]byte) bool { return bytes.Compare(value[:], target[:]) <= 0 }
func ticket(cookie [32]byte, nonce uint64, bits int) bool {
	var n [8]byte
	binary.LittleEndian.PutUint64(n[:], nonce)
	h := w1.Hash("public-ticket-v3", cookie[:], n[:])
	return binary.BigEndian.Uint32(h[:4])>>uint(32-bits) == 0
}
func measure(index, workCap, falseCap, cookieCap int) (map[string]any, error) {
	a, b := make([]uint32, w1.Cells), make([]uint32, w1.Cells)
	task := w1.Hash("task", words(a), words(b))
	var target [32]byte
	for i := range target {
		target[i] = 255
	}
	target[0] = 127
	var challenge [32]byte
	var good []byte
	attempts := 0
	t, c, ok := start()
	for nonce := 0; nonce < workCap; nonce++ {
		var seed [16]byte
		binary.LittleEndian.PutUint64(seed[:8], uint64(index))
		binary.LittleEndian.PutUint64(seed[8:], uint64(nonce))
		challenge = w1.Hash("go-cost-same-statement-challenge-v1", seed[:])
		p, err := w1.Proof(challenge, a, b)
		if err != nil {
			return nil, err
		}
		attempts++
		h := w1.Hash("ticket", challenge[:], p[w1.ProofBytes-32:])
		if qualified(h, target) {
			good = p
			break
		}
	}
	honestCost := elapsed(t, c, ok)
	if good == nil {
		return nil, errors.New("HONEST_EXHAUSTED")
	}
	t, c, ok = start()
	valid := w1.Verify(challenge, task, target, good)
	validCost := elapsed(t, c, ok)
	if valid != nil {
		return nil, fmt.Errorf("HONEST:%w", valid)
	}
	prefix := append(append(append([]byte("PNW1"), words(a)...), words(b)...), make([]byte, w1.Cells*4)...)
	var bad []byte
	falseAttempts := 0
	t, c, ok = start()
	for nonce := 0; nonce < falseCap; nonce++ {
		var n [8]byte
		binary.LittleEndian.PutUint64(n[:], uint64(nonce))
		trace := w1.Hash("public-v3-from-zero-v1", challenge[:], n[:])
		h := w1.Hash("ticket", challenge[:], trace[:])
		falseAttempts++
		if qualified(h, target) {
			bad = append(prefix, trace[:]...)
			break
		}
	}
	falseCost := elapsed(t, c, ok)
	if bad == nil {
		return nil, errors.New("FALSE_EXHAUSTED")
	}
	if err := w1.Precheck(challenge, task, target, bad); err != nil {
		return nil, fmt.Errorf("PRECHECK:%w", err)
	}
	t, c, ok = start()
	invalid := w1.Verify(challenge, task, target, bad)
	invalidCost := elapsed(t, c, ok)
	if invalid == nil || invalid.Error() != "Transcript" {
		return nil, fmt.Errorf("FALSE_ACCEPT:%v", invalid)
	}
	cookies := []any{}
	for _, bits := range []int{8, 12, 16} {
		id := w1.Hash("synthetic-v3-cookie-id-go-research", challenge[:], []byte{byte(bits)})
		t, c, ok = start()
		trials := 0
		found := false
		for nonce := 0; nonce < cookieCap; nonce++ {
			trials++
			if ticket(id, uint64(nonce), bits) {
				found = true
				break
			}
		}
		cost := elapsed(t, c, ok)
		var ratio any
		fns, goodF := invalidCost["process_cpu_ns"].(int64)
		cns, goodC := cost["process_cpu_ns"].(int64)
		ans, goodA := falseCost["process_cpu_ns"].(int64)
		if found && goodF && goodC && goodA && cns+ans > 0 {
			ratio = float64(fns) / float64(cns+ans)
		}
		cookies = append(cookies, map[string]any{"bits": bits, "trials": trials, "capped": !found, "search": cost, "cookie_id_sha256": hexHash(id[:]), "receiver_cpu_over_fake_plus_cookie_cpu": ratio})
	}
	return map[string]any{"sample_index": index, "challenge": hex.EncodeToString(challenge[:]), "task": hex.EncodeToString(task[:]), "target": hex.EncodeToString(target[:]), "material": "canonical-zero", "honest_attempts": attempts, "honest_search": honestCost, "honest_verify": validCost, "honest_proof_sha256": hexHash(good), "false_attempts": falseAttempts, "false_search": falseCost, "false_reject": invalidCost, "false_result": "Transcript", "false_proof_sha256": hexHash(bad), "synthetic_cookie_searches": cookies}, nil
}
func main() {
	n := flag.Int("samples", 3, "1..64 bounded samples")
	work := flag.Int("work-cap", 32, "1..256 complete W1 attempts")
	fake := flag.Int("false-cap", 128, "1..4096 fake trace attempts")
	cookie := flag.Int("cookie-cap", 262144, "1..1048576 cookie attempts")
	out := flag.String("out", "", "optional new, never overwritten report path")
	flag.Parse()
	if *n < 1 || *n > 64 || *work < 1 || *work > 256 || *fake < 1 || *fake > 4096 || *cookie < 1 || *cookie > 1048576 || len(flag.Args()) != 0 {
		fmt.Fprintln(os.Stderr, "BOUNDS")
		os.Exit(2)
	}
	runtime.GOMAXPROCS(1)
	rows := []any{}
	for i := 0; i < *n; i++ {
		v, e := measure(i, *work, *fake, *cookie)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
		rows = append(rows, v)
	}
	report := map[string]any{"schema": "pon-w1-cookie-go-cost-v1", "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "logical_cpus": runtime.NumCPU(), "go_max_procs": runtime.GOMAXPROCS(0), "cpu_scope": "Linux RUSAGE_SELF whole process incl Go GC; not Rust/WAN/GPU", "signed_v3_cookie": false, "gpu_cost": nil, "independent_accepted": false, "production_activation": false, "samples": rows}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		panic(err)
	}
	raw = append(raw, '\n')
	if *out == "" {
		os.Stdout.Write(raw)
		return
	}
	file, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		panic(err)
	}
	if _, err = file.Write(raw); err != nil {
		file.Close()
		panic(err)
	}
	if err = file.Sync(); err != nil {
		file.Close()
		panic(err)
	}
	if err = file.Close(); err != nil {
		panic(err)
	}
}
