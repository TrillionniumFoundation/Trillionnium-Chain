package w1

import (
    "crypto/sha256"
    "encoding/binary"
    "encoding/hex"
    "testing"
)
func assertHex(t *testing.T, value [32]byte, expected string){
    t.Helper()
    if hex.EncodeToString(value[:])!=expected{t.Fatalf("want %s got %x",expected,value)}
}
func TestThirdLanguageExactW1Proof(t *testing.T){
    var challenge [32]byte
    for i:=range challenge{challenge[i]=byte(i)}
    a,b:=make([]uint32,Cells),make([]uint32,Cells)
    for i:=range a{a[i]=uint32(i%97);b[i]=uint32(i%83)}
    task:=Hash("task",fieldBytes(a),fieldBytes(b))
    assertHex(t,task,"cac3c5379382194f355a87a5625a46d86241f0d491305a21c95a5d1c795e90da")
    proof,err:=Proof(challenge,a,b)
    if err!=nil{t.Fatal(err)}
    assertHex(t,sha256.Sum256(proof),"b6d53b8205e0f9c1054541722fd517b73dab3235810fa65195b8074f153ffb04")
    var trace [32]byte;copy(trace[:],proof[ProofBytes-32:])
    assertHex(t,trace,"01c964f77a54e08bf174888a15c25ed0aea7756ced4b90bb8bebc26745b0d46e")
    var target [32]byte;for i:=range target{target[i]=255}
    if err:=Verify(challenge,task,target,proof);err!=nil{t.Fatal(err)}
}
func TestFourNoWorkFalseTranscriptSameStatement(t *testing.T){
    var challenge,target [32]byte
    for i:=range challenge{challenge[i]=byte(i);target[i]=255}
    target[0]=127
    zeros:=make([]uint32,Cells)
    task:=Hash("task",fieldBytes(zeros),fieldBytes(zeros))
    assertHex(t,task,"6618f8a794517852f621993ccb6ac311c684e1db2b9d1d47166fa00a744c4c29")
    expected:=[]string{
        "e20adbeeda03ed387f4a0ddb92be0210c56047c19f4bbf3768df51619a8c7888",
        "516f779a970c30a78736aecece4fa24d2c55f9932ceaf27657ac2903367464b8",
        "70882ef88c393f966c8f58f51dbf953045e7ba09bae4ea3ab9590e19afe0e720",
        "23490d58b41f730b287d9eeaef73e9308dc8f3057ec591fbcbd00981a3ac768d",
    }
    prefix:=make([]byte,ProofBytes-32);copy(prefix,[]byte("PNW1"))
    for nonce:=0;nonce<4;nonce++{
        var n [8]byte;binary.LittleEndian.PutUint64(n[:],uint64(nonce))
        trace:=Hash("public-v3-from-zero-v1",challenge[:],n[:])
        if hex.EncodeToString(trace[:])!=expected[nonce]{t.Fatalf("trace %d mismatch",nonce)}
        proof:=append(append([]byte{},prefix...),trace[:]...)
        if err:=Precheck(challenge,task,target,proof);err!=nil{t.Fatal(err)}
        if err:=Verify(challenge,task,target,proof);err==nil||err.Error()!="Transcript"{
            t.Fatalf("false proof %d wrongly accepted: %v",nonce,err)
        }
    }
}
func TestEarlyAndLateRejectionOrder(t *testing.T){
    var challenge,target [32]byte
    for i:=range challenge{challenge[i]=byte(i);target[i]=255}
    a,b:=make([]uint32,Cells),make([]uint32,Cells)
    for i:=range a{a[i]=uint32(i%97);b[i]=uint32(i%83)}
    task:=Hash("task",fieldBytes(a),fieldBytes(b))
    proof,err:=Proof(challenge,a,b);if err!=nil{t.Fatal(err)}
    check:=func(wire []byte,c,tgtTask,tgt [32]byte,expected string){
        t.Helper();err:=Verify(c,tgtTask,tgt,wire)
        if err==nil||err.Error()!=expected{t.Fatalf("expected %s got %v",expected,err)}
    }
    check(proof[:len(proof)-1],challenge,task,target,"Length")
    bad:=append([]byte{},proof...);bad[0]^=1
    check(bad,challenge,task,target,"Version")
    bad=append([]byte{},proof...);binary.LittleEndian.PutUint32(bad[4:],uint32(Q))
    check(bad,challenge,task,target,"Field")
    changedTask:=task;changedTask[0]^=1
    check(proof,challenge,changedTask,target,"Task")
    check(proof,challenge,task,[32]byte{},"Target")
    bad=append([]byte{},proof...);bad[len(bad)-1]^=1
    check(bad,challenge,task,target,"Transcript")
    bad=append([]byte{},proof...)
    at:=4+2*Cells*4
    first:=binary.LittleEndian.Uint32(bad[at:])
    binary.LittleEndian.PutUint32(bad[at:],uint32((uint64(first)+1)%Q))
    check(bad,challenge,task,target,"Product")
}
func TestW2CWorkTicketIsNotAValidW1Transcript(t *testing.T){
    seed:=Hash("w2c-research-header",[]byte("A"))
    header:=make([]byte,0,318)
    for i:=0;i<9;i++{header=append(header,seed[:]...)}
    header=append(header,make([]byte,30)...)
    assertHex(t,sha256.Sum256(header),"bf9f9e1a7443cae2f2b2da449f197d10dc9eab89d7426886c81e142df41a6d37")
    challenge:=Hash("challenge",header)
    proof:=make([]byte,ProofBytes);copy(proof,[]byte("PNW1"))
    trace:=Hash("w2c-false-trace",challenge[:])
    copy(proof[ProofBytes-32:],trace[:])
    commitment:=Hash("w2c-proposal",[]byte("w2c-research-security-v0"),header,proof)
    assertHex(t,commitment,"4068356fd3bc37585ad640e23e1040cd96c2b60a9ed3b987854f0f2469637589")
    var n [8]byte;binary.LittleEndian.PutUint64(n[:],0)
    ticket:=Hash("w2c-security",[]byte("w2c-research-security-v0"),commitment[:],n[:])
    assertHex(t,ticket,"b2a270922619282e262ca045856a413f0b33ac0400d91045bdc1ec8a40a79fb6")
    z:=make([]byte,Cells*4);task:=Hash("task",z,z)
    var tgt [32]byte;for i:=range tgt{tgt[i]=255}
    if err:=Verify(challenge,task,tgt,proof);err==nil||err.Error()!="Transcript"{t.Fatalf("false W1 after W2C: %v",err)}
}
