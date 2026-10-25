// Package w1 independently checks the experimental W1 arithmetic and bytes.
// It cannot admit a block, spend chainwork, authorize models, or replace Rust.
package w1

import (
    "bytes"
    "crypto/sha256"
    "encoding/binary"
    "errors"
    "hash"
)

const (
    N = 64
    R = 8
    Cells = N * N
    Q uint64 = 4294967291
    ProofBytes = 4 + 3*Cells*4 + 32
)

func Hash(tag string, parts ...[]byte) [32]byte {
    h := sha256.New()
    h.Write([]byte("TRNM-PON1\x00"))
    var len2 [2]byte
    binary.LittleEndian.PutUint16(len2[:], uint16(len(tag)))
    h.Write(len2[:])
    h.Write([]byte(tag))
    var len4 [4]byte
    for _, part := range parts {
        binary.LittleEndian.PutUint32(len4[:], uint32(len(part)))
        h.Write(len4[:])
        h.Write(part)
    }
    var result [32]byte
    copy(result[:], h.Sum(nil))
    return result
}

func fieldDecode(data []byte) ([]uint32, error) {
    if len(data)%4 != 0 { return nil, errors.New("Length") }
    values := make([]uint32, len(data)/4)
    for i := range values {
        v := binary.LittleEndian.Uint32(data[4*i:])
        if uint64(v) >= Q { return nil, errors.New("Field") }
        values[i] = v
    }
    return values, nil
}

func fieldBytes(values []uint32) []byte {
    result := make([]byte, len(values)*4)
    for i,v := range values { binary.LittleEndian.PutUint32(result[4*i:],v) }
    return result
}

func expand(challenge [32]byte, label byte, length int) ([]uint32,error) {
    out := make([]uint32, 0, length)
    for counter:=uint32(0); len(out)<length; counter++ {
        if counter>=128 { return nil,errors.New("NoiseBudget") }
        var nonce [4]byte
        binary.LittleEndian.PutUint32(nonce[:],counter)
        block := Hash("noise",challenge[:],[]byte{label},nonce[:])
        for j:=0;j<8 && len(out)<length;j++ {
            value:=binary.LittleEndian.Uint32(block[4*j:])
            if uint64(value)<Q {out=append(out,value)}
        }
    }
    return out,nil
}

// mul uses independently reduced uint64 products rather than Rust's u128.
// Sum and each product are reduced before addition to avoid overflow.
func mul(a,b []uint32, rows, inner, cols int) []uint32 {
    out:=make([]uint32,rows*cols)
    for i:=0;i<rows;i++ {
        for j:=0;j<cols;j++ {
            var sum uint64
            for k:=0;k<inner;k++ {
                term:=(uint64(a[i*inner+k])*uint64(b[k*cols+j]))%Q
                sum=(sum+term)%Q
            }
            out[i*cols+j]=uint32(sum)
        }
    }
    return out
}

func add(a,b []uint32) []uint32 {
    result:=make([]uint32,len(a))
    for i:=range a {result[i]=uint32((uint64(a[i])+uint64(b[i]))%Q)}
    return result
}

func validateMaterial(a,b []uint32) error {
    if len(a)!=Cells || len(b)!=Cells {return errors.New("Length")}
    for _,v:=range a {if uint64(v)>=Q {return errors.New("Field")}}
    for _,v:=range b {if uint64(v)>=Q {return errors.New("Field")}}
    return nil
}

// Compute replays all 512 transcript tiles with independent modular arithmetic.
// It is only a research arithmetic function; no Node/cumulative-work capability.
func Compute(challenge [32]byte, a,b []uint32)([]uint32,[32]byte,error){
    var noTrace [32]byte
    if err:=validateMaterial(a,b);err!=nil{return nil,noTrace,err}
    noises:=make([][]uint32,4)
    for label:=0;label<4;label++ {
        var err error
        noises[label],err=expand(challenge,byte(label),N*R)
        if err!=nil{return nil,noTrace,err}
    }
    el,er,fl,fr:=noises[0],noises[1],noises[2],noises[3]
    ap:=add(a,mul(el,er,N,R,N))
    bp:=add(b,mul(fl,fr,N,R,N))
    cp:=make([]uint32,Cells)
    trace:=sha256.New()
    writeTracePrefix(trace,challenge)
    var buf [4]byte
    for bi:=0;bi<N/R;bi++ {
        for bj:=0;bj<N/R;bj++ {
            for bk:=0;bk<N/R;bk++ {
                for i:=bi*R;i<(bi+1)*R;i++ {
                    for j:=bj*R;j<(bj+1)*R;j++ {
                        at:=i*N+j
                        sum:=uint64(cp[at])
                        for k:=bk*R;k<(bk+1)*R;k++ {
                            term:=(uint64(ap[i*N+k])*uint64(bp[k*N+j]))%Q
                            sum=(sum+term)%Q
                        }
                        cp[at]=uint32(sum)
                        binary.LittleEndian.PutUint32(buf[:],cp[at])
                        trace.Write(buf[:])
                    }
                }
            }
        }
    }
    part1:=mul(mul(a,fl,N,N,R),fr,N,R,N)
    part2:=mul(el,mul(er,bp,R,N,N),N,R,N)
    result:=make([]uint32,Cells)
    for i:=range result {
        x:=(uint64(cp[i])+Q-uint64(part1[i]))%Q
        result[i]=uint32((x+Q-uint64(part2[i]))%Q)
    }
    copy(noTrace[:],trace.Sum(nil))
    return result,noTrace,nil
}

func writeTracePrefix(h hash.Hash,challenge [32]byte) {
    h.Write([]byte("TRNM-PON-TRACE1\x00"))
    h.Write(challenge[:])
}

func Precheck(challenge,task,target [32]byte,proof []byte)error{
    if len(proof)!=ProofBytes{return errors.New("Length")}
    if !bytes.Equal(proof[:4],[]byte("PNW1")){return errors.New("Version")}
    if target==([32]byte{}){return errors.New("Target")}
    _,err:=fieldDecode(proof[4:ProofBytes-32]);if err!=nil{return err}
    observedTask:=Hash("task",proof[4:4+Cells*4],proof[4+Cells*4:4+2*Cells*4])
    if task!=observedTask{return errors.New("Task")}
    ticket:=Hash("ticket",challenge[:],proof[ProofBytes-32:])
    if bytes.Compare(ticket[:],target[:])>0{return errors.New("Target")}
    return nil
}

func Verify(challenge,task,target [32]byte,proof []byte)error{
    if err:=Precheck(challenge,task,target,proof);err!=nil{return err}
    a,_:=fieldDecode(proof[4:4+Cells*4])
    b,_:=fieldDecode(proof[4+Cells*4:4+2*Cells*4])
    c,trace,err:=Compute(challenge,a,b)
    if err!=nil{return err}
    if !bytes.Equal(trace[:],proof[ProofBytes-32:]){return errors.New("Transcript")}
    if !bytes.Equal(fieldBytes(c),proof[4+2*Cells*4:ProofBytes-32]){
        return errors.New("Product")
    }
    return nil
}

func Proof(challenge [32]byte,a,b []uint32)([]byte,error){
    c,trace,err:=Compute(challenge,a,b);if err!=nil{return nil,err}
    result:=make([]byte,0,ProofBytes)
    result=append(result,[]byte("PNW1")...)
    result=append(result,fieldBytes(a)...)
    result=append(result,fieldBytes(b)...)
    result=append(result,fieldBytes(c)...)
    result=append(result,trace[:]...)
    if len(result)!=ProofBytes{return nil,errors.New("Length")}
    return result,nil
}
