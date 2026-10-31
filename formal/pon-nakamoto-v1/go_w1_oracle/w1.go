// Package w1 independently verifies W1 mathematical bytes for cross-language
// differential research. It cannot admit blocks, grant work or authorize models.
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
    Cells = N*N
    Q uint64 = 4294967291
    ProofBytes = 4+3*Cells*4+32
)
func Hash(tag string, parts ...[]byte) [32]byte {
    h:=sha256.New()
    h.Write([]byte("TRNM-PON1\x00"))
    var l2 [2]byte
    binary.LittleEndian.PutUint16(l2[:],uint16(len(tag)))
    h.Write(l2[:]);h.Write([]byte(tag))
    var l4 [4]byte
    for _,p:=range parts {
        binary.LittleEndian.PutUint32(l4[:],uint32(len(p)))
        h.Write(l4[:]);h.Write(p)
    }
    var x [32]byte;copy(x[:],h.Sum(nil));return x
}
func fieldDecode(src []byte)([]uint32,error){
    if len(src)%4!=0{return nil,errors.New("Length")}
    a:=make([]uint32,len(src)/4)
    for i:=range a {
        x:=binary.LittleEndian.Uint32(src[4*i:])
        if uint64(x)>=Q{return nil,errors.New("Field")}
        a[i]=x
    }
    return a,nil
}
func fieldBytes(v []uint32)[]byte{
    out:=make([]byte,len(v)*4)
    for i,x:=range v {binary.LittleEndian.PutUint32(out[i*4:],x)}
    return out
}
func expand(c [32]byte,label byte,length int)([]uint32,error){
    out:=make([]uint32,0,length)
    for count:=uint32(0);len(out)<length;count++{
        if count>=128{return nil,errors.New("NoiseBudget")}
        var b [4]byte;binary.LittleEndian.PutUint32(b[:],count)
        block:=Hash("noise",c[:],[]byte{label},b[:])
        for j:=0;j<8&&len(out)<length;j++{
            n:=binary.LittleEndian.Uint32(block[4*j:])
            if uint64(n)<Q{out=append(out,n)}
        }
    }
    return out,nil
}
// Deliberately use modular u64 products rather than Rust's u128 accumulator.
func multiply(a,b []uint32,rows,inner,cols int)[]uint32{
    out:=make([]uint32,rows*cols)
    for i:=0;i<rows;i++{
        for j:=0;j<cols;j++{
            var sum uint64
            for k:=0;k<inner;k++{
                term:=(uint64(a[i*inner+k])*uint64(b[k*cols+j]))%Q
                sum=(sum+term)%Q
            }
            out[i*cols+j]=uint32(sum)
        }
    }
    return out
}
func add(a,b []uint32)[]uint32{
    out:=make([]uint32,len(a))
    for i:=range out{out[i]=uint32((uint64(a[i])+uint64(b[i]))%Q)}
    return out
}
func validate(a,b []uint32)error{
    if len(a)!=Cells||len(b)!=Cells{return errors.New("Length")}
    for _,s:=range [][]uint32{a,b}{
        for _,x:=range s{if uint64(x)>=Q{return errors.New("Field")}}
    }
    return nil
}
func tracePrefix(h hash.Hash,c [32]byte){
    h.Write([]byte("TRNM-PON-TRACE1\x00"));h.Write(c[:])
}
func Compute(c [32]byte,a,b []uint32)([]uint32,[32]byte,error){
    var empty [32]byte
    if err:=validate(a,b);err!=nil{return nil,empty,err}
    noise:=make([][]uint32,4)
    for i:=range noise{
        v,err:=expand(c,byte(i),N*R)
        if err!=nil{return nil,empty,err}
        noise[i]=v
    }
    el,er,fl,fr:=noise[0],noise[1],noise[2],noise[3]
    ap:=add(a,multiply(el,er,N,R,N))
    bp:=add(b,multiply(fl,fr,N,R,N))
    cp:=make([]uint32,Cells)
    h:=sha256.New();tracePrefix(h,c)
    var buf [4]byte
    for bi:=0;bi<N/R;bi++{
        for bj:=0;bj<N/R;bj++{
            for bk:=0;bk<N/R;bk++{
                for i:=bi*R;i<(bi+1)*R;i++{
                    for j:=bj*R;j<(bj+1)*R;j++{
                        pos:=i*N+j
                        sum:=uint64(cp[pos])
                        for k:=bk*R;k<(bk+1)*R;k++{
                            term:=(uint64(ap[i*N+k])*uint64(bp[k*N+j]))%Q
                            sum=(sum+term)%Q
                        }
                        cp[pos]=uint32(sum)
                        binary.LittleEndian.PutUint32(buf[:],cp[pos])
                        h.Write(buf[:])
                    }
                }
            }
        }
    }
    left:=multiply(multiply(a,fl,N,N,R),fr,N,R,N)
    right:=multiply(el,multiply(er,bp,R,N,N),N,R,N)
    result:=make([]uint32,Cells)
    for i:=range result{
        x:=(uint64(cp[i])+Q-uint64(left[i]))%Q
        result[i]=uint32((x+Q-uint64(right[i]))%Q)
    }
    copy(empty[:],h.Sum(nil))
    return result,empty,nil
}
func Precheck(c,task,target [32]byte,proof []byte)error{
    if len(proof)!=ProofBytes{return errors.New("Length")}
    if !bytes.Equal(proof[:4],[]byte("PNW1")){return errors.New("Version")}
    if target==([32]byte{}){return errors.New("Target")}
    if _,err:=fieldDecode(proof[4:ProofBytes-32]);err!=nil{return err}
    expected:=Hash("task",proof[4:4+Cells*4],proof[4+Cells*4:4+2*Cells*4])
    if task!=expected{return errors.New("Task")}
    ticket:=Hash("ticket",c[:],proof[ProofBytes-32:])
    if bytes.Compare(ticket[:],target[:])>0{return errors.New("Target")}
    return nil
}
func Verify(c,task,target [32]byte,proof []byte)error{
    if err:=Precheck(c,task,target,proof);err!=nil{return err}
    a,_:=fieldDecode(proof[4:4+Cells*4])
    b,_:=fieldDecode(proof[4+Cells*4:4+2*Cells*4])
    prod,trace,err:=Compute(c,a,b)
    if err!=nil{return err}
    if !bytes.Equal(trace[:],proof[ProofBytes-32:]){return errors.New("Transcript")}
    if !bytes.Equal(fieldBytes(prod),proof[4+2*Cells*4:ProofBytes-32]){
        return errors.New("Product")
    }
    return nil
}
func Proof(c [32]byte,a,b []uint32)([]byte,error){
    product,trace,err:=Compute(c,a,b)
    if err!=nil{return nil,err}
    out:=make([]byte,0,ProofBytes)
    out=append(out,[]byte("PNW1")...)
    out=append(out,fieldBytes(a)...)
    out=append(out,fieldBytes(b)...)
    out=append(out,fieldBytes(product)...)
    out=append(out,trace[:]...)
    return out,nil
}
