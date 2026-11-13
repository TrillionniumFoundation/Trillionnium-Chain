// Command daaoracle streams exact ASERT research results as bounded JSONL.
// This executable never mines blocks, verifies W1, or selects chain rules.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"trillionnium.org/research/daaoracle"
)

type reply struct {
	Target string `json:"target,omitempty"`
	Error  string `json:"error,omitempty"`
}

func main() {
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 4096), 16384)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for scan.Scan() {
		line := scan.Bytes()
		r := reply{}
		var in daaoracle.Input
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if e := dec.Decode(&in); e != nil {
			r.Error = "ASERT_RESEARCH_INPUT"
		} else if dec.Decode(new(any)) != io.EOF {
			r.Error = "ASERT_RESEARCH_INPUT"
		} else {
			target, e := daaoracle.ASERT(in)
			if e != nil {
				r.Error = e.Error()
			} else {
				r.Target = daaoracle.EncodeHex32(target)
			}
		}
		b, _ := json.Marshal(r)
		fmt.Fprintln(out, string(b))
	}
	if e := scan.Err(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(2)
	}
}
