"""Full public API differential against the unchanged original Rust crate."""
from pathlib import Path
import struct
from .fixtures import record
from .qualification_support import error_code as errcode


def run(suite):
    cp0=record();cp1=record(1,predecessor=cp0[640:]);cp2=record(2,predecessor=cp1[640:]);cp3=record(3,predecessor=cp2[640:])
    root=suite.root; p=suite.pair('complete')
    p.path(11,'journal');p.call(13,normalize_path=True);p.call(15);empty=p.call(14)[1];p.call(1,empty);p.call(2,empty);p.call(3,empty);p.call(16,bytes(32));p.call(16,bytes([2])*32);p.call(17,struct.pack('<Q',0)+bytes(672)+cp0);p.call(16,cp0[16:48]);pin=p.call(14)[1];p.call(17,struct.pack('<Q',0)+bytes(672)+cp0);p.call(17,struct.pack('<Q',1)+cp0+cp2);p.call(17,struct.pack('<Q',1)+cp0+cp1);p.call(19)
    # Failed constructor and structural serve consume all original FD lifetimes.
    for _ in range(4):p.path(11,'journal')
    p.path(12,'journal',empty);p.path(10,'journal');p.path(18,'unused-socket');p.path(10,'journal');p.call(14);p.call(19)
    p.path(5,'pin',pin);p.path(4,'pin');p.path(5,'pin',pin)
    for n in (0,1,83,85,84*100):p.call(1,bytes(n),label='pin-length')
    for bit in (0,8,9,12,20,52,83):
     altered=bytearray(pin);altered[bit]^=1;p.call(1,bytes(altered),label='pin-byte')
    p.path(40,'ledger',cp0);h=p.call(42)[1];p.call(44,cp0+cp1);p.call(43,cp0+cp1);p.call(43,cp0+cp1);p.call(44,cp0+cp1);p.call(45);p.path(41,'ledger',cp0+cp1);p.call(42);p.call(43,cp1+cp2);p.call(44,cp0+cp1);p.call(42);p.call(43,cp2+cp3);p.call(45)
    p.path(41,'ledger',cp0+cp2);p.path(41,'ledger',cp1+cp2);p.call(45)
    for owner in (p.na,p.nb):(owner/'cp').write_bytes(cp0)
    p.path(50,'cp');p.path(30,'socket');p.call(31,struct.pack('<QQ',0,0));p.call(32,normalize_path=True);p.call(38)
    for errno in [*range(134),255,4095,(1<<32)+1,(1<<32)+2,(1<<32)+3,(1<<32)+4,(1<<32)+0x104,(1<<32)+0x204,(1<<32)+0x305,(1<<32)+0x404]:p.call(60,struct.pack('<QQ',errcode('io','Unix transport'),errno),label='error-display')
    p.call(62);p.close()
