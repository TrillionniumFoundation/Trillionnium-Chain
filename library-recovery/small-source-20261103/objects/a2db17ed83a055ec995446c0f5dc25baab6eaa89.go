//go:build linux

// Research-only W1/Cookie same-host CPU study; no signed Cookie or consensus authority.
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

type Measured struct {
    CPU *uint64 `json:"process_cpu_ns"`
    Wall uint64 `json:"wall_ns"`
}
func cpuNS() (*uint64,error) {
    var usage syscall.Rusage
    if err:=syscall.Getrusage(syscall.RUSAGE_SELF,&usage);err!=nil {return nil,err}
    if usage.Utime.Sec<0||usage.Stime.Sec<0||usage.Utime.Usec<0||usage.Stime.Usec<0{return nil,errors.New("invalid CPU stamp")}
    total:=uint64(usage.Utime.Sec+usage.Stime.Sec)*1_000_000_000 + uint64(usage.Utime.Usec+usage.Stime.Usec)*1000
    return &total,nil
}
func measure(fn func() error)(Measured,error){
    begin,err:=cpuNS();if err!=nil{return Measured{},err}
    start:=time.Now();callErr:=fn();end,stampErr:=cpuNS()
    if stampErr!=nil{return Measured{},stampErr}
    if *end<*begin{return Measured{},errors.New("cpu counter rewind")}
    total:=*end-*begin
    return Measured{CPU:&total,Wall:uint64(time.Since(start).Nanoseconds())},callErr
}
func digest(v []byte)string {h:=sha256.Sum256(v);return hex.EncodeToString(h[:])}
func nonceBytes(n uint64)[]byte {var b [8]byte;binary.LittleEndian.PutUint64(b[:],n);return b[:]}
func cookiePass(ticket [32]byte,bits uint)bool {return binary.BigEndian.Uint32(ticket[:4])>>(32-bits)==0}
func hashPass(ticket,target [32]byte)bool{return !bytes.Equal(target[:],make([]byte,32))&&bytes.Compare(ticket[:],target[:])<=0}

type Row struct {
    Sample int `json:"sample"`
    Task string `json:"task"`
    Challenge string `json:"challenge"`
    Target string `json:"target"`
    HonestAttempts uint64 `json:"honest_attempts"`
    HonestSearch Measured `json:"honest_full_producer_search"`
    HonestValidation Measured `json:"honest_w1_validation"`
    HonestValid bool `json:"honest_verified"`
    FalseAttempts uint64 `json:"false_trace_attempts_to_four_hits"`
    FalseSearch Measured `json:"false_trace_search_total"`
    FalseCases []any `json:"four_forgery_cases"`
    Cookie []any `json:"synthetic_cookie_costs"`
}
func runSample(sample int, maxHonest, maxFalse, maxCookie uint64,bits []uint)(Row,error){
    var target [32]byte;for i:=range target{target[i]=255};target[0]=127
    zeros:=make([]uint32,w1.Cells)
    raw:=make([]byte,w1.Cells*4)
    task:=w1.Hash("task",raw,raw)
    row:=Row{Sample:sample,Task:hex.EncodeToString(task[:]),Target:hex.EncodeToString(target[:]),FalseCases:[]any{},Cookie:[]any{}}
    var winning []byte
    var challenge [32]byte
    var trials uint64
    cost,err:=measure(func()error{
        for n:=uint64(0);n<maxHonest;n++{
            trials++
            challenge=w1.Hash("w1-go-cost-challenge-v1",nonceBytes(uint64(sample)),nonceBytes(n))
            proof,proveErr:=w1.Proof(challenge,zeros,zeros);if proveErr!=nil{return proveErr}
            var trace [32]byte;copy(trace[:],proof[len(proof)-32:])
            ticket:=w1.Hash("ticket",challenge[:],trace[:])
            if hashPass(ticket,target){winning=proof;break}
        };return nil
    });if err!=nil{return row,err}
    row.HonestAttempts=trials;row.HonestSearch=cost
    if winning==nil{return row,errors.New("no honest candidate in cap")}
    row.Challenge=hex.EncodeToString(challenge[:]);row.HonestValid=false
    cost,err=measure(func()error{return w1.Verify(challenge,task,target,winning)})
    row.HonestValidation=cost;row.HonestValid=err==nil;if err!=nil{return row,err}
    var falseProofs [][]byte
    var search uint64
    searchCost,err:=measure(func()error{
        for n:=uint64(0);n<maxFalse;n++{
            search++
            trace:=w1.Hash("public-v3-from-zero-v1",challenge[:],nonceBytes(n))
            ticket:=w1.Hash("ticket",challenge[:],trace[:])
            if hashPass(ticket,target){
                proof:=make([]byte,w1.ProofBytes);copy(proof[:4],[]byte("PNW1"))
                copy(proof[w1.ProofBytes-32:],trace[:]);falseProofs=append(falseProofs,proof)
                if len(falseProofs)==4{break}
            }
        };return nil
    });if err!=nil{return row,err}
    row.FalseSearch=searchCost;row.FalseAttempts=search
    if len(falseProofs)!=4{return row,errors.New("four fakes not reached before cap")}
    for index,proof:=range falseProofs{
        var outcome string
        cost,err=measure(func()error{
            check:=w1.Verify(challenge,task,target,proof)
            if check==nil{return errors.New("forged full W1 was accepted")}
            outcome=check.Error()
            if outcome!="Transcript"{return fmt.Errorf("unexpected error %s",outcome)}
            return nil
        });if err!=nil{return row,err}
        row.FalseCases=append(row.FalseCases,map[string]any{"case":index,"proof_sha256":digest(proof),"trace":hex.EncodeToString(proof[w1.ProofBytes-32:]),"outcome":outcome,"verified_work":false,"full_replay":cost})
    }
    cookie:=w1.Hash("w1-go-cost-synthetic-cookie-v1",challenge[:])
    for _,b:=range bits{
        attempts:=uint64(0);found:=false
        cost,err=measure(func()error{
            for n:=uint64(0);n<maxCookie;n++{
                attempts++
                ticket:=w1.Hash("public-ticket-v3",cookie[:],nonceBytes(n))
                if cookiePass(ticket,b){found=true;break}
            };return nil
        });if err!=nil{return row,err}
        row.Cookie=append(row.Cookie,map[string]any{"bits":b,"attempts":attempts,"cap":maxCookie,"status":map[bool]string{true:"HIT",false:"CAPPED"}[found],"synthetic_cookie_id":hex.EncodeToString(cookie[:]),"cost":cost})
    }
    return row,nil
}
func main(){
    samples:=flag.Int("samples",2,"number of samples 1..16")
    hon:=flag.Uint64("honest-cap",128,"maximum legal full-proof challenge attempts")
    fakes:=flag.Uint64("false-cap",128,"maximum false trace hash attempts")
    cookie:=flag.Uint64("cookie-cap",262144,"maximum SHA256 Cookie attempts")
    output:=flag.String("out","","create-only JSON output; stdout if absent")
    flag.Parse()
    if *samples<1||*samples>16||*hon<1||*hon>4096||*fakes<4||*fakes>4096||*cookie<1||*cookie>1048576{fmt.Fprintln(os.Stderr,"invalid bounded options");os.Exit(2)}
    runtime.GOMAXPROCS(1)
    rows:=make([]Row,0,*samples)
    for i:=0;i<*samples;i++ {row,err:=runSample(i+1,*hon,*fakes,*cookie,[]uint{8,12,16});if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)};rows=append(rows,row)}
    report:=map[string]any{"schema":"w1-cookie-go-same-process-cpu-research-v1","source":"Go exact independent W1 oracle SHA 0d2f14c492c2644b26478429d036fbee66e06220","platform":runtime.GOOS,"arch":runtime.GOARCH,"go_version":runtime.Version(),"original_w1_consensus_changed":false,"native_Rust_implementation":false,"signed_V3_cookie":false,"gpu_hashrate_measured":false,"actual_network":false,"independent_operator":false,"production_activation":false,"cpu_scope":"RUSAGE_SELF process user+system CPU, includes Go runtime, excludes hardware power and sibling processes","rows":rows}
    encoded,err:=json.MarshalIndent(report,"","  ");if err!=nil{panic(err)}
    encoded=append(encoded,'\n')
    if *output!="" {f,err:=os.OpenFile(*output,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600);if err!=nil{panic(err)};defer f.Close();if _,err=f.Write(encoded);err!=nil{panic(err)};if err=f.Sync();err!=nil{panic(err)}}else{os.Stdout.Write(encoded)}
}
