package w1

import (
    "bytes"
    "crypto/sha256"
    "encoding/hex"
    "encoding/binary"
    "testing"
)

func wantHex(t *testing.T, got [32]byte, expected string) {
    t.Helper()
    if hex.EncodeToString(got[:])!=expected {
        t.Fatalf("hash mismatch: %x != %s",got,expected)
    }
}

func TestThirdLanguageW1ProofReferenceVector(t *testing.T){
    var c [32]byte
    for i:=range c {c[i]=byte(i)}
    a,b:=make([]uint32,Cells),make([]uint32,Cells)
    for i:=range a {a[i]=uint32(i%97);b[i]=uint32(i%83)}
    task:=Hash("task",fieldBytes(a),fieldBytes(b))
    wantHex(t,task,"cac3c5379382194f355a87a5625a46d86241f0d491305a21c95a5d1c795e90da")
    proof,err:=Proof(c,a,b)
    if err!=nil{t.Fatal(err)}
    wantHex(t,sha256.Sum256(proof),"b6d53b8205e0f9c1054541722fd517b73dab3235810fa65195b8074f153ffb04")
    var trace [32]byte
    copy(trace[:],proof[ProofBytes-32:])
    wantHex(t,trace,"01c964f77a54e08bf174888a15c25ed0aea7756ced4b90bb8bebc26745b0d46e")
    var target [32]byte
    for i:=range target{target[i]=255}
    if err:=Verify(c,task,target,proof);err!=nil{t.Fatal(err)}
}

func TestFourCheapW1TracesAllReplayReject(t *testing.T){
    var challenge [32]byte
    for i:=range challenge{challenge[i]=byte(i)}
    zeros:=make([]uint32,Cells)
    task:=Hash("task",fieldBytes(zeros),fieldBytes(zeros))
    wantHex(t,task,"6618f8a794517852f621993ccb6ac311c684e1db2b9d1d47166fa00a744c4c29")
    var target [32]byte
    for i:=range target{target[i]=0xff};target[0]=0x7f
    expected:=[]string{
        "e20adbeeda03ed387f4a0ddb92be0210c56047c19f4bbf3768df51619a8c7888",
        "516f779a970c30a78736aecece4fa24d2c55f9932ceaf27657ac2903367464b8",
        "70882ef88c393f966c8f58f51dbf953045e7ba09bae4ea3ab9590e19afe0e720",
        "23490d58b41f730b287d9eeaef73e9308dc8f3057ec591fbcbd00981a3ac768d",
    }
    prefix:=make([]byte,ProofBytes-32)
    copy(prefix,[]byte("PNW1"))
    for nonce:=0;nonce<4;nonce++{
        var n [8]byte
        binary.LittleEndian.PutUint64(n[:],uint64(nonce))
        trace:=Hash("public-v3-from-zero-v1",challenge[:],n[:])
        if hex.EncodeToString(trace[:])!=expected[nonce]{t.Fatal("trace digest mismatch")}
        proof:=append(append([]byte{},prefix...),trace[:]...)
        if err:=Precheck(challenge,task,target,proof);err!=nil{
            t.Fatal("false trace did not pass precheck",err)
        }
        if err:=Verify(challenge,task,target,proof);err==nil || err.Error()!="Transcript"{
            t.Fatalf("fake proof accepted or wrong rejection: %v",err)
        }
    }
}

func TestW2CSecurityOnlyNotW1(t *testing.T){
    seed:=Hash("w2c-research-header",[]byte("A"))
    header:=make([]byte,0,318)
    for i:=0;i<9;i++{header=append(header,seed[:]...)}
    header=append(header,make([]byte,30)...)
    wantHex(t,sha256.Sum256(header),"bf9f9e1a7443cae2f2b2da449f197d10dc9eab89d7426886c81e142df41a6d37")
    challenge:=Hash("challenge",header)
    proof:=make([]byte,ProofBytes);copy(proof,[]byte("PNW1"))
    trace:=Hash("w2c-false-trace",challenge[:]);copy(proof[ProofBytes-32:],trace[:])
    wantHex(t,sha256.Sum256(proof),"3d24f79389c76cd71ad16455709878a740f18af1da851498288ef2001dd6cd49")
    p:=Hash("w2c-proposal",[]byte("w2c-research-security-v0"),header,proof)
    wantHex(t,p,"4068356fd3bc37585ad640e23e1040cd96c2b60a9ed3b987854f0f2469637589")
    for _,v:=range []struct{n uint64;hex string}{
        {0,"b2a270922619282e262ca045856a413f0b33ac0400d91045bdc1ec8a40a79fb6"},
        {1,"51edd0c15496b7e132cbb30e4111d32d33c9407482cfa4432b5c92fe4616bee1"},
    }{
        var n [8]byte
        binary.LittleEndian.PutUint64(n[:],v.n)
        ticket:=Hash("w2c-security",[]byte("w2c-research-security-v0"),p[:],n[:])
        wantHex(t,ticket,v.hex)
    }
    var target [32]byte;for i:=range target{target[i]=255}
    z:=make([]byte,Cells*4)
    task:=Hash("task",z,z)
    if err:=Verify(challenge,task,target,proof);err==nil||err.Error()!="Transcript"{
        t.Fatalf("invalid W1 after security commitment: %v",err)
    }
    if bytes.Equal(proof[ProofBytes-32:],make([]byte,32)){
        t.Fatal("must contain forged nonzero trace")
    }
}
