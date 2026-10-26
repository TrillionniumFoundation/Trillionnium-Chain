// Command w1_verify_go is an independent, deliberately bounded scalar verifier
// for Trillionnium's experimental PNW1 work transcript. It never mines,
// validates chain State, approves a task, or grants any consensus authority.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

const (
	matrixN            = 64
	tileN              = 8
	matrixCells        = matrixN * matrixN
	modulus     uint64 = 4294967291
	proofLength        = 4 + 3*matrixCells*4 + 32
)

type digest [32]byte

type verdict struct {
	Schema             string `json:"schema"`
	Status             string `json:"status"`
	Error              string `json:"error,omitempty"`
	Ticket             string `json:"ticket,omitempty"`
	ProductHash        string `json:"product_sha256,omitempty"`
	VerificationWallNS int64  `json:"verification_wall_ns"`
	ProofBytes         int    `json:"proof_bytes"`
}

func h(tag string, parts ...[]byte) digest {
	sum := sha256.New()
	_, _ = sum.Write([]byte("TRNM-PON1\x00"))
	var len2 [2]byte
	binary.LittleEndian.PutUint16(len2[:], uint16(len(tag)))
	_, _ = sum.Write(len2[:])
	_, _ = sum.Write([]byte(tag))
	var len4 [4]byte
	for _, item := range parts {
		binary.LittleEndian.PutUint32(len4[:], uint32(len(item)))
		_, _ = sum.Write(len4[:])
		_, _ = sum.Write(item)
	}
	var out digest
	copy(out[:], sum.Sum(nil))
	return out
}

func decodeHex32(src, field string) (digest, error) {
	var out digest
	if len(src) != 64 {
		return out, fmt.Errorf("%s_LENGTH", field)
	}
	b, err := hex.DecodeString(src)
	if err != nil {
		return out, fmt.Errorf("%s_HEX", field)
	}
	copy(out[:], b)
	return out, nil
}

func decodeProof(data []byte) ([]uint32, []uint32, []uint32, digest, error) {
	if len(data) != proofLength {
		return nil, nil, nil, digest{}, errors.New("LENGTH")
	}
	if string(data[:4]) != "PNW1" {
		return nil, nil, nil, digest{}, errors.New("VERSION")
	}
	words := make([]uint32, 3*matrixCells)
	for i := range words {
		words[i] = binary.LittleEndian.Uint32(data[4+i*4 : 8+i*4])
		if uint64(words[i]) >= modulus {
			return nil, nil, nil, digest{}, errors.New("FIELD")
		}
	}
	var trace digest
	copy(trace[:], data[len(data)-32:])
	return words[:matrixCells], words[matrixCells : 2*matrixCells], words[2*matrixCells:], trace, nil
}

func fieldBytes(values []uint32) []byte {
	out := make([]byte, 4*len(values))
	for i, v := range values {
		binary.LittleEndian.PutUint32(out[i*4:(i+1)*4], v)
	}
	return out
}

func expandNoise(challenge digest, label byte) ([]uint32, error) {
	out := make([]uint32, 0, matrixN*tileN)
	for counter := uint32(0); counter < 128 && len(out) < cap(out); counter++ {
		var n [4]byte
		binary.LittleEndian.PutUint32(n[:], counter)
		block := h("noise", challenge[:], []byte{label}, n[:])
		for j := 0; j < 8 && len(out) < cap(out); j++ {
			word := binary.LittleEndian.Uint32(block[j*4 : (j+1)*4])
			if uint64(word) < modulus {
				out = append(out, word)
			}
		}
	}
	if len(out) != matrixN*tileN {
		return nil, errors.New("NOISE_BUDGET")
	}
	return out, nil
}

func modAdd(a, b uint32) uint32 { return uint32((uint64(a) + uint64(b)) % modulus) }
func modMulAcc(acc uint32, x, y uint32) uint32 {
	// Each product is < 2^64, and each modular addition < 2*q.
	// Reduce per-product; never overflow uint64 when summing 8 or 64 terms.
	return uint32((uint64(acc) + (uint64(x)*uint64(y))%modulus) % modulus)
}

func product(a, b []uint32, rows, inner, columns int) []uint32 {
	out := make([]uint32, rows*columns)
	for i := 0; i < rows; i++ {
		for k := 0; k < inner; k++ {
			for j := 0; j < columns; j++ {
				ix := i*columns + j
				out[ix] = modMulAcc(out[ix], a[i*inner+k], b[k*columns+j])
			}
		}
	}
	return out
}

func transcript(challenge digest, a, b []uint32) (digest, error) {
	el, e := expandNoise(challenge, 0)
	if e != nil {
		return digest{}, e
	}
	er, e := expandNoise(challenge, 1)
	if e != nil {
		return digest{}, e
	}
	fl, e := expandNoise(challenge, 2)
	if e != nil {
		return digest{}, e
	}
	fr, e := expandNoise(challenge, 3)
	if e != nil {
		return digest{}, e
	}
	em := product(el, er, matrixN, tileN, matrixN)
	fm := product(fl, fr, matrixN, tileN, matrixN)
	aa := make([]uint32, matrixCells)
	bb := make([]uint32, matrixCells)
	for i := range aa {
		aa[i] = modAdd(a[i], em[i])
		bb[i] = modAdd(b[i], fm[i])
	}
	cp := make([]uint32, matrixCells)
	sha := sha256.New()
	_, _ = sha.Write([]byte("TRNM-PON-TRACE1\x00"))
	_, _ = sha.Write(challenge[:])
	var word [4]byte
	for i0 := 0; i0 < matrixN; i0 += tileN {
		for j0 := 0; j0 < matrixN; j0 += tileN {
			for k0 := 0; k0 < matrixN; k0 += tileN {
				for i := i0; i < i0+tileN; i++ {
					for j := j0; j < j0+tileN; j++ {
						pos := i*matrixN + j
						acc := cp[pos]
						for k := k0; k < k0+tileN; k++ {
							acc = modMulAcc(acc, aa[i*matrixN+k], bb[k*matrixN+j])
						}
						cp[pos] = acc
						binary.LittleEndian.PutUint32(word[:], acc)
						_, _ = sha.Write(word[:])
					}
				}
			}
		}
	}
	var result digest
	copy(result[:], sha.Sum(nil))
	return result, nil
}

func verify(challenge, expectedTask, target digest, data []byte) (digest, digest, error) {
	a, b, claimedProduct, claimedTrace, err := decodeProof(data)
	if err != nil {
		return digest{}, digest{}, err
	}
	task := h("task", fieldBytes(a), fieldBytes(b))
	if task != expectedTask {
		return digest{}, digest{}, errors.New("TASK")
	}
	if target == (digest{}) {
		return digest{}, digest{}, errors.New("TARGET")
	}
	ticket := h("ticket", challenge[:], claimedTrace[:])
	// SHA256 digest lexicographic order equals BE256 unsigned order.
	for i := 0; i < 32; i++ {
		if ticket[i] < target[i] {
			break
		}
		if ticket[i] > target[i] {
			return digest{}, digest{}, errors.New("TARGET")
		}
	}
	actualTrace, err := transcript(challenge, a, b)
	if err != nil {
		return digest{}, digest{}, err
	}
	if claimedTrace != actualTrace {
		return digest{}, digest{}, errors.New("TRANSCRIPT")
	}
	actualProduct := product(a, b, matrixN, matrixN, matrixN)
	for i := range actualProduct {
		if claimedProduct[i] != actualProduct[i] {
			return digest{}, digest{}, errors.New("PRODUCT")
		}
	}
	return ticket, sha256.Sum256(fieldBytes(actualProduct)), nil
}

func readProof(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("PROOF_NOT_FILE")
	}
	if st.Size() != proofLength {
		return nil, errors.New("LENGTH")
	}
	raw, e := io.ReadAll(io.LimitReader(f, proofLength+1))
	if e != nil {
		return nil, e
	}
	if len(raw) != proofLength {
		return nil, errors.New("LENGTH")
	}
	return raw, nil
}

func main() {
	challengeHex := flag.String("challenge", "", "canonical 32-byte challenge hex")
	taskHex := flag.String("task", "", "canonical 32-byte task hex")
	targetHex := flag.String("target", "", "canonical 32-byte target hex")
	path := flag.String("proof-file", "", "path to exactly 49188 PNW1 bytes")
	flag.Parse()
	out := verdict{Schema: "trnm-w1-go-scalar-verifier-research-v1", Status: "refused"}
	var err error
	var challenge, task, target digest
	challenge, err = decodeHex32(*challengeHex, "CHALLENGE")
	if err == nil {
		task, err = decodeHex32(*taskHex, "TASK")
	}
	if err == nil {
		target, err = decodeHex32(*targetHex, "TARGET")
	}
	var data []byte
	if err == nil {
		data, err = readProof(*path)
	}
	out.ProofBytes = len(data)
	if err == nil {
		start := time.Now()
		var ticket, prod digest
		ticket, prod, err = verify(challenge, task, target, data)
		out.VerificationWallNS = time.Since(start).Nanoseconds()
		if err == nil {
			out.Status = "verified"
			out.Ticket = hex.EncodeToString(ticket[:])
			out.ProductHash = hex.EncodeToString(prod[:])
		}
	}
	if err != nil {
		out.Error = err.Error()
	}
	enc := json.NewEncoder(os.Stdout)
	if e := enc.Encode(out); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
	if err != nil {
		os.Exit(1)
	}
}
