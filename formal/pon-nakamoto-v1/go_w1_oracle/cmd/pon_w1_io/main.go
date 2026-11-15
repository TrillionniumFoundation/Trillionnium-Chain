// Research-only bounded Go differential bridge. No consensus or chainwork.
package main
import(
    "encoding/binary"
    "errors"
    "fmt"
    "io"
    "os"
    w1 "trillionnium/pon-w1-research-oracle"
)
func field(raw []byte)([]uint32,error){
    if len(raw)!=w1.Cells*4{return nil,errors.New("Length")}
    vals:=make([]uint32,w1.Cells)
    for i:=range vals{
        vals[i]=binary.LittleEndian.Uint32(raw[i*4:])
        if uint64(vals[i])>=w1.Q{return nil,errors.New("Field")}
    }
    return vals,nil
}
func run(mode string,raw []byte)([]byte,error){
    switch mode{
    case "prove":
        if len(raw)!=32+2*w1.Cells*4{return nil,errors.New("Length")}
        var challenge [32]byte;copy(challenge[:],raw[:32])
        a,err:=field(raw[32:32+w1.Cells*4]);if err!=nil{return nil,err}
        b,err:=field(raw[32+w1.Cells*4:]);if err!=nil{return nil,err}
        return w1.Proof(challenge,a,b)
    case "verify":
        if len(raw)!=96+w1.ProofBytes{return nil,errors.New("Length")}
        var c,task,target [32]byte
        copy(c[:],raw[:32]);copy(task[:],raw[32:64]);copy(target[:],raw[64:96])
        if err:=w1.Verify(c,task,target,raw[96:]);err!=nil{return nil,err}
        digest:=w1.Hash("w2-go-oracle-receipt-test-only",raw)
        return digest[:],nil
    default:
        return nil,errors.New("Mode")
    }
}
func main(){
    if len(os.Args)!=2{fmt.Fprintln(os.Stderr,"usage: pon_w1_io prove|verify");os.Exit(2)}
    raw,err:=io.ReadAll(io.LimitReader(os.Stdin,96+w1.ProofBytes+1))
    if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
    out,err:=run(os.Args[1],raw)
    if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
    if _,err:=os.Stdout.Write(out);err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
}
