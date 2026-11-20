"""Targeted original scalar arithmetic cases; only a separate private ELF accepts them."""
import struct,json
U64=(1<<64)-1;I128_MIN=-(1<<127);I128_MAX=(1<<127)-1;I64_MIN=-(1<<63);I64_MAX=(1<<63)-1
BURST=2_000_000_000;RESERVE=100_000_000;MAGIC=0x3130303055504350
def halves(value):
 value%=1<<128;return value&U64,value>>64
def boundary_cases():
 result=[]
 def add(name,method,*,credit=BURST,count=0,unavailable=0,term=0,completions=0,flow=True,
         old=(100,500_000_000),now=None,measured=0,total=0,residual=None,full=None,already=None,
         cold=0,changes=None):
  if now is None:now=old
  booked=count*RESERVE
  initial=credit+booked+term
  if not I128_MIN<=initial<=I128_MAX:initial=credit
  state=[MAGIC,unavailable,*halves(credit),old[0]&U64,old[1],count,term,completions,int(flow),
         *halves(initial),0,0,booked&U64,0,0,0,0,0]
  if changes:
   for index,value in changes.items():state[index]=value
  values=[0x3130305849464350,method,*state,now[0]&U64,now[1],measured,total,
    int(residual is not None),residual or 0,int(full is not None and already is not None),
    full or 0,already or 0,cold]+[0]*32
  if len(values)!=64 or not all(0<=x<=U64 for x in values):raise ValueError('Invalid complete private arithmetic frame')
  result.append({'name':name,'method':method,'frame_hex':struct.pack('<64Q',*values).hex(),
                 'seed_words':values,'qualification_only_caller_counters':True})
 add('init-warm-negative-time',0,credit=0,old=(-7,0),now=(-3,1))
 add('init-cold-near-signed-min',0,cold=1,old=(I64_MIN+1,3),now=(I64_MIN+2,7))
 add('init-warm-near-signed-max',0,old=(I64_MAX-2,3),now=(I64_MAX-1,7))
 add('refill-unchanged-watermark',1)
 add('refill-stale-seconds',1,credit=400_000_000,now=(99,999_999_999))
 add('refill-stale-nanos',1,credit=-5,now=(100,499_999_999))
 add('refill-rounded-three-nanos',1,credit=0,now=(100,500_000_003))
 add('refill-four-nanos',1,credit=0,now=(100,500_000_004))
 add('refill-nanosecond-borrow',1,credit=0,old=(-1,999_999_999),now=(0,3))
 add('refill-two-reserve-ceiling',1,credit=1_700_000_000,count=2,now=(101,500_000_000))
 add('refill-termination-ceiling',1,credit=1_600_000_000,count=2,term=25_000_000,now=(104,500_000_000))
 add('refill-debt-wider-than-u64',1,credit=-(1<<90),now=(1000,0))
 add('refill-full-signed-timespec-span',1,credit=0,old=(I64_MIN+1_000_000_000,999_999_999),now=(I64_MAX-1_000_000_000,0))
 add('refill-i128-positive-overflow-updates-watermark',1,credit=I128_MAX,now=(100,500_000_004))
 add('refill-cap-discards-invalid-positive-telemetry',1,credit=BURST+1)
 add('refill-credited-flow-overflow',1,credit=0,now=(100,500_000_004),changes={12:U64})
 add('refill-discarded-flow-overflow',1,now=(100,500_000_004),changes={13:U64})
 add('reserve-warm-owned-principal',2)
 add('reserve-exact-purchased-quantum',2,credit=RESERVE)
 add('reserve-one-nanosecond-short',2,credit=RESERVE-1)
 add('reserve-two-owner-limit-after-refill',2,count=2,credit=1_600_000_000,now=(101,0))
 add('reserve-completion-fence',2,completions=1,credit=RESERVE)
 add('reserve-already-unavailable-still-refills',2,unavailable=1,credit=0,now=(101,0))
 add('reserve-booked-telemetry-overflow',2,changes={14:U64})
 add('charge-known-debt-retained',3,credit=5,count=1,measured=10)
 add('charge-i128-negative-overflow',3,credit=I128_MIN,count=1,measured=1)
 add('charge-stale-clock-still-debits',3,credit=10,count=1,measured=4,now=(99,0))
 add('charge-already-unavailable-still-debits',3,credit=10,count=1,measured=4,unavailable=1)
 add('charge-live-flow-overflow',3,credit=10,count=1,measured=1,changes={15:U64})
 add('request-missing-reservation-before-refill',4,credit=0,count=0,measured=1,total=1,now=(1000,0))
 add('request-impossible-reservations-before-refill',4,count=3,measured=1,total=1,now=(1000,0))
 add('request-cumulative-regression-before-refill',4,count=1,measured=2,total=1,now=(1000,0))
 add('request-one-reserve-exact-floor',4,credit=-RESERVE+7,count=1,measured=7,total=7)
 add('request-one-reserve-below-floor',4,credit=-RESERVE+6,count=1,measured=7,total=7)
 add('request-two-reserve-exact-floor',4,credit=-2*RESERVE+7,count=2,measured=7,total=RESERVE)
 add('request-two-reserve-below-floor',4,credit=-2*RESERVE+6,count=2,measured=7,total=RESERVE)
 add('request-past-own-quantum-protects-other-reserve',4,credit=-2*RESERVE+7,count=2,measured=7,total=RESERVE+1)
 add('request-past-own-quantum-exact-own-floor',4,credit=-RESERVE+7,count=2,measured=7,total=RESERVE+1)
 add('final-lost-reservation-no-refill',5,credit=10,count=0,measured=4,now=(1000,0))
 add('final-impossible-count-no-refill',5,credit=10,count=3,measured=4,now=(1000,0))
 add('final-lost-underflow-preserves-flow-until-error',5,credit=I128_MIN,count=0,measured=1,now=(1000,0))
 add('final-already-unavailable-refills-and-debits',5,credit=0,count=0,measured=4,unavailable=1,now=(101,0))
 add('settle-unowned-before-refill',6,count=0,credit=10,residual=0,full=0,already=0,now=(1000,0))
 add('settle-impossible-count-before-refill',6,count=3,credit=10,residual=0,full=0,already=0,now=(1000,0))
 add('settle-unknown-does-not-refund',6,count=1,credit=1_900_000_000)
 add('settle-known-unique-residual',6,count=1,credit=1_890_000_000,residual=3,full=10_000_003,already=10_000_000,changes={15:10_000_000})
 add('settle-full-less-than-already-drops-only-flow',6,count=1,credit=1_900_000_000,residual=3,full=2,already=3)
 add('settle-attribution-mismatch-drops-only-flow',6,count=1,credit=1_900_000_000,residual=3,full=7,already=1)
 add('settle-no-attribution-drops-only-flow',6,count=1,credit=1_900_000_000,residual=0)
 add('settle-already-unavailable-keeps-known-refund',6,count=1,credit=1_900_000_000,unavailable=1,residual=3,full=3,already=0)
 add('settle-stale-i128-refund-overflow',6,count=1,credit=I128_MAX,residual=0,full=0,already=0,now=(99,0))
 add('settle-stale-i128-debit-overflow',6,count=1,credit=I128_MIN,residual=U64,full=U64,already=0,now=(99,0))
 add('settle-stale-cap-discard',6,count=2,credit=1_900_000_000,residual=0,full=0,already=0,now=(99,0))
 add('settle-booked-telemetry-underflow',6,count=1,credit=1_900_000_000,residual=0,full=0,already=0,changes={14:RESERVE-1})
 add('settle-residual-telemetry-overflow',6,count=1,credit=1_900_000_000,residual=1,full=1,already=0,changes={16:U64})
 add('settle-full-telemetry-overflow',6,count=1,credit=1_900_000_000,residual=1,full=1,already=0,changes={17:U64})
 add('flow-valid-negative-shared-credit',7,count=2,credit=-RESERVE)
 add('flow-mismatched-booked-count',7,count=2,credit=-RESERVE,changes={14:RESERVE})
 add('flow-paid-sum-overflow',7,changes={15:U64,16:1})
 add('flow-paid-less-than-settled',7,changes={17:1})
 add('freshness-valid-earned-principal',8,credit=0,now=(101,0))
 add('freshness-stale-watermark',8,now=(99,0))
 add('freshness-unavailable-no-projection',8,unavailable=1,credit=0,now=(101,0))
 add('freshness-above-ceiling-no-projection',8,credit=BURST+1)
 add('freshness-age-not-u64-nanoseconds',8,credit=0,old=(-1_000_000_000_000,0),now=(0,0))
 add('freshness-offered-i128-overflow',8,credit=I128_MAX,now=(100,500_000_004))
 add('freshness-telemetry-overflow',8,credit=0,now=(100,500_000_004),changes={12:U64})
 if len({r['name'] for r in result})!=len(result):raise ValueError('Duplicate private arithmetic case')
 return result


def owner_cases():
 rows=[
 ("serial-owner",0,1,[(1,4,100000,19),(1,0,0,0)]),
 ("two-by-two",0,2,[(2,4,50000,7),(2,4,50000,11)]),
 ("four-workers",0,1,[(4,8,50000,23),(1,0,0,0)]),
 ("maximal-eighteen-children",0,2,[(8,8,50000,29),(8,8,50000,31)]),
 ("zero-transactions",0,1,[(8,0,1,41),(1,0,0,0)]),
 ("cold-start-refusal",1,2,[(8,8,1000,43),(8,8,1000,47)]),
 ]
 return [{"name":name,"plan":{"cold":cold,"requests":requests,
  "profiles":[dict(zip(("workers","txs","units","seed"),p)) for p in profiles]}} for name,cold,requests,profiles in rows]

def fault_cases():
 return [
  {"name":"constructor-clock1-eio","injection":["clock_gettime:error=EIO:when=1"],"workers":1,"txs":1,"expected_exit":101},
  {"name":"reserve-clock1-eio","injection":["clock_gettime:error=EIO:when=2"],"workers":1,"txs":1,"expected_exit":0},
  {"name":"live-clock3-einval","injection":["clock_gettime:error=EINVAL:when=3"],"workers":1,"txs":1,"expected_exit":0},
  {"name":"live-clock3-eio-fallback","injection":["clock_gettime:error=EIO:when=3"],"workers":1,"txs":1,"expected_exit":0},
  {"name":"outer-clock3-einval","injection":["clock_gettime:error=EINVAL:when=5"],"workers":1,"txs":0,"expected_exit":0},
  {"name":"settlement-clock1-eio","injection":["clock_gettime:error=EIO:when=6"],"workers":1,"txs":0,"expected_exit":0},
  {"name":"worker-global-request-clock1-einval","injection":["clock_gettime:error=EINVAL:when=3"],"workers":2,"txs":2,"expected_exit":0},
  {"name":"partial-worker-two-start","injection":["clone:error=EAGAIN:when=2"],"workers":4,"txs":4,"expected_exit":0},
  {"name":"partial-worker-four-start","injection":["clone:error=EAGAIN:when=4"],"workers":4,"txs":4,"expected_exit":0},
  {"name":"owner-first-start-refused","injection":["clone:error=EAGAIN:when=1"],"workers":1,"txs":1,"expected_exit":90},
  {"name":"live-clock3-invalid-timespec","injection":["clock_gettime:retval=0:poke_exit=@arg2=000000000000000000ca9a3b00000000:when=3"],"workers":1,"txs":1,"expected_exit":0},
  {"name":"reserve-clock1-invalid-timespec","injection":["clock_gettime:retval=0:poke_exit=@arg2=000000000000000000ca9a3b00000000:when=2"],"workers":1,"txs":1,"expected_exit":0},
  {"name":"partial-start-priority-over-clock-panic","injection":["clone:error=EAGAIN:when=2","clock_gettime:error=EINVAL:when=3"],"workers":4,"txs":4,"expected_exit":0},
 ]


def original_fault_cases():
 result=[]
 for case in fault_cases():
  row={key:case[key] for key in ("name","workers","txs")}
  for rule in case["injection"]:
   items=rule.split(":");when=int(items[-1].split("=")[1])
   if items[0]=="clone":
    row.update(clone_role=4 if case["name"]=="owner-first-start-refused" else 2,clone_when=when)
   else:
    constructor=case["name"]=="constructor-clock1-eio"
    row.update(clock_roles=[1] if constructor else [2,3],clock_when="constructor-final" if constructor else when)
    if "retval=0" in rule:row["clock_invalid"]=True
    else:row["clock_error"]={"EIO":5,"EINVAL":22}[items[1].split("=")[1]]
  result.append(row)
 return result
