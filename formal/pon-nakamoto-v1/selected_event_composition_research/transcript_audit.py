"""Reconstructed typed-pointer ledger; observed traces do not certify lifetime caps."""
from collections import Counter,defaultdict
from exact_cost import decode_hash,ref

def classify(message):
    try:tag,parts=decode_hash(message)
    except ValueError:return 'other',None,[]
    lens=tuple(map(len,parts));n=len(ref.PROFILE);profile=bool(parts) and parts[0]==ref.PROFILE
    if tag==b'leaf' and lens==(n,1,1,256) and profile:
        if parts[1] in (b'A',b'B') and parts[2][0]<64:return 'leaf','merkle',[]
    if tag==b'node' and lens==(n,1,1,32,32) and profile:
        if parts[1] in (b'A',b'B') and parts[2][0]<6:
            return 'node','merkle',[('merkle',parts[3]),('merkle',parts[4])]
    if tag==b'task' and lens==(n,32,32) and profile:
        return 'task','task',[('merkle',parts[1]),('merkle',parts[2])]
    if tag==b'context' and lens==(n,32,32,32,32,32) and profile:
        return 'context','context',[('task',parts[4])]
    if tag==b'noise-seed' and lens==(32,8):return 'noise-seed','seed',[('context',parts[0])]
    if tag==b'selected-coordinate' and lens==(32,):return 'selected-coordinate',None,[('seed',parts[0])]
    if tag==b'noise-eight' and lens==(32,2,4) and parts[1][0]<4 and parts[1][1]<64:
        return 'noise-eight',None,[('seed',parts[0])]
    if tag==b'event' and lens==(32,8,3,256,256) and all(v<8 for v in parts[2]):
        return 'event','event',[('context',parts[0])]
    if tag==b'ticket' and lens==(32,):return 'ticket',None,[('event',parts[0])]
    return 'other',None,[]

class Audit:
    def __init__(self):
        self.inputs={};self.outputs={};self.pointers=defaultdict(set)
        self.domain_counts=Counter();self.exceptions=[]
    def add(self,message,digest):
        if len(digest)!=32:raise ValueError('digest size')
        tag,producer,pointers=classify(message)
        for kind,value in pointers:self.pointers[kind].add(value)
        if message in self.inputs:
            if self.inputs[message]!=digest:raise ValueError('inconsistent oracle')
            return []
        self.domain_counts[tag]+=1;events=[]
        if digest in self.outputs:events.append('OUTPUT_COLLISION')
        if producer is not None and digest in self.pointers[producer]:
            events.append('REVERSE_POINTER_'+producer.upper())
        self.inputs[message]=digest;self.outputs[digest]=message
        if events:self.exceptions.append({'query_index':len(self.inputs),'tag':tag,'events':events,'digest':digest.hex()})
        return events
