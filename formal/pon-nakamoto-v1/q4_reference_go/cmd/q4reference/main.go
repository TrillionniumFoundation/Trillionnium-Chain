// q4reference independently checks Q4's fixed double-signature wire contract.
// WARNING: outputs are research observations, not Node-verified authority.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	q4 "example.org/trnm/pon/q4-reference-research"
)

type request struct {
	Network           string `json:"network"`
	Parameters        string `json:"parameters"`
	OldLease          string `json:"old_lease"`
	OldStatement      string `json:"old_source_statement"`
	SignedTransaction string `json:"signed_transaction"`
	ContainingHeight  uint64 `json:"containing_height"`
}

func parse(s string, n int) ([]byte, error) {
	if len(s) != n*2 {
		return nil, fmt.Errorf("hex length %d, expected %d", len(s), n*2)
	}
	b, e := hex.DecodeString(s)
	if e != nil || hex.EncodeToString(b) != s {
		return nil, fmt.Errorf("hex must be canonical lowercase")
	}
	return b, nil
}
func run(data []byte) (any, error) {
	if len(data) > 8192 {
		return nil, fmt.Errorf("oversize research input")
	}
	var v request
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("trailing or multiple JSON values")
	}
	n, err := parse(v.Network, 32)
	if err != nil {
		return nil, err
	}
	p, err := parse(v.Parameters, 32)
	if err != nil {
		return nil, err
	}
	old, err := parse(v.OldLease, q4.LeaseBytes)
	if err != nil {
		return nil, err
	}
	source, err := parse(v.OldStatement, q4.StatementBytes)
	if err != nil {
		return nil, err
	}
	tx, err := parse(v.SignedTransaction, q4.EnvelopeBytes)
	if err != nil {
		return nil, err
	}
	var net, params q4.Digest
	copy(net[:], n)
	copy(params[:], p)
	o, err := q4.Validate(q4.Input{Network: net, Parameters: params, OldLease: old,
		OldSourceStatement: source, RenewalTransaction: tx, ContainingHeight: v.ContainingHeight})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"scope":               "independent-q4-research-wire-crypto-only-not-consensus-authority",
		"transaction_id":      hex.EncodeToString(o.TransactionID[:]),
		"successor_lease_id":  hex.EncodeToString(o.LeaseID[:]),
		"source_statement_id": hex.EncodeToString(o.SourceStatementID[:]),
		"requester_pubkey":    hex.EncodeToString(o.Requester[:]),
		"source_pubkey":       hex.EncodeToString(o.Source[:]),
		"slot":                o.Slot, "old_revision": o.PreviousRevision, "successor_revision": o.SuccessorRevision,
		"earliest_height": o.FromHeight, "last_containing_height": o.LastContainingHeight,
	}, nil
}
func main() {
	input, err := io.ReadAll(io.LimitReader(os.Stdin, 8193))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	out, err := run(input)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Q4 reference refused:", err)
		os.Exit(2)
	}
	if err = json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
}
