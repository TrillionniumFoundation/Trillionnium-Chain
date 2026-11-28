"""Strict framing and diagnostics; no values here are runtime CPU authority."""
from __future__ import annotations
import struct
from .build import need

PLAN_MAGIC=0x3130304d4f444350
ACCOUNT_MAGIC=0x3130304343414350
OWNER_MAGIC=0x3130304e574f4350
BUDGET_MAGIC=0x3130303055504350

def frame(plan):
 need(type(plan) is dict and set(plan)=={"cold","requests","profiles"},"Incomplete finite work plan")
 need(type(plan["cold"]) is int and plan["cold"] in (0,1)
      and type(plan["requests"]) is int and plan["requests"] in (1,2),"Invalid finite epoch/owner profile")
 need(type(plan["profiles"]) is list and len(plan["profiles"])==2,"Both active/inactive work profiles are mandatory")
 values=[PLAN_MAGIC,plan["cold"],plan["requests"],0]
 for profile in plan["profiles"]:
  need(type(profile) is dict and set(profile)=={"workers","txs","units","seed"},"Incomplete work profile")
  need(all(type(profile[k]) is int for k in profile),"Work plan integers required")
  need(profile["workers"] in (1,2,4,8) and 0<=profile["txs"]<=32 and 0<=profile["units"]<=1_000_000
       and 0<=profile["seed"]<(1<<64),"Outside finite work profile")
  values.extend(profile[k] for k in ("workers","txs","units","seed"))
 return struct.pack("<24Q",*values,*([0]*12))

def plan_from_frame(raw):
 need(len(raw)==192,"Work plan must be exactly 192 bytes")
 w=struct.unpack("<24Q",raw)
 plan={"cold":w[1],"requests":w[2],"profiles":[dict(zip(("workers","txs","units","seed"),w[4+4*i:8+4*i])) for i in range(2)]}
 need(frame(plan)==raw,"Noncanonical work plan, reserved word or magic")
 return plan

def words(raw):
 need(len(raw)==1536,"A complete epoch diagnostic is exactly 1536 bytes")
 value=struct.unpack("<192Q",raw)
 need(value[0]==ACCOUNT_MAGIC and value[8]==BUDGET_MAGIC,"Epoch/account diagnostic magic differs")
 return value

def work_value(request,transaction,units,seed):
 value=seed^transaction^(request+1)
 for step in range(units):value=(value*1664525+1013904223+step)&((1<<64)-1)
 return value

def positive_receipt(raw,plan):
 w=words(raw);g=w[:64];state=w[8:28]
 need(g[1:7]==(0,plan["requests"],plan["requests"],plan["requests"],0,0),"Positive epoch did not finish every actual owner")
 need(state[1]==0 and state[6:10]==(0,0,0,1),"Positive epoch remains unavailable/unsettled")
 owners=[]
 for request in range(2):
  row=w[(request+1)*64:(request+2)*64]
  if request>=plan["requests"]:
   need(not any(row),"Absent request returned an owner diagnostic");continue
  need(row[0]==OWNER_MAGIC and row[1]==request and row[21]==2+request*9 and row[22]==0,"Owner identity/panic differs")
  if row[2]:
   need(plan["cold"]==1 and row[2]==2 and row[3]==0 and row[19]==1,"Unexpected begin refusal")
   need(not any(row[i] for i in (4,6,8,10,12,14,15,16,17)),"Refused begin fabricated a settlement")
   owners.append({"request":request,"kind":"BEGIN_REFUSED","actual_tid":row[20],"life":row[21]});continue
  need(row[3]==0 and all(row[i]==1 for i in (4,6,8,10,12)) and row[18]==row[19]==0,"Positive operation failed or became Unknown")
  profile=plan["profiles"][request];count=min(profile["workers"],profile["txs"]);count=count if count>1 else 0
  need(row[14:18]==(count,)*4 and row[5]>0 and (row[7]>0)==(count>0),"Actual scoped interval counts differ")
  need(row[9]==row[5]+row[7] and row[9]>=row[11] and row[13]==row[9]-row[11],"Actual full CPU or unique residual differs")
  need(row[23]==(1<<profile["txs"])-1,"Actual joined work mask differs")
  need(all(row[24+i]==work_value(request,i,profile["units"],profile["seed"]) for i in range(profile["txs"])),
       "Actual native HIA body differs")
  need(not any(row[24+profile["txs"]:]),"Extra work outputs")
  owners.append({"request":request,"kind":"SETTLED","actual_tid":row[20],"life":row[21],
   "owner_cpu_ns":row[5],"scoped_worker_cpu_ns":row[7],"total_cpu_ns":row[9],
   "live_paid_cpu_ns":row[11],"residual_cpu_ns":row[13],"scoped_workers":count})
 credit=signed(state[2],state[3]);initial=signed(state[10],state[11])
 need(initial==(0 if plan["cold"] else 2_000_000_000),"Wrong original initial principal")
 need(state[14]==0 and credit==initial+state[12]-state[15]-state[16]-state[18],"Signed complete flow identity differs")
 need(state[17]==state[15]+state[16]==sum(o.get("total_cpu_ns",0) for o in owners),"Shared paid CPU union differs")
 return {"owners":owners,"credit_ns":str(credit),"initial_credit_ns":str(initial),
  "credited_refill_ns":state[12],"discarded_refill_ns":state[13],"paid_cpu_ns":state[17],
  "cold_start_may_earn_original_credit_before_actual_reserve":True}

def signed(low,high):
 v=low+(high<<64);return v-(1<<128) if high>>63 else v
def decode_boundary(raw):
 need(len(raw)==376,'Complete boundary receipt missing')
 w=struct.unpack('<47Q',raw);need(w[0]==0x313030554f464350,'Boundary output magic differs')
 state=w[2:22];flow=w[22:38];fresh=w[38:47]
 need(state[0]==0x3130303055504350 and state[1] in (0,1) and state[9] in (0,1),'Boundary state identity differs')
 value={'result':w[1],'credit_ns':str(signed(state[2],state[3])),'unavailable':bool(state[1]),
   'updated_seconds_bits':state[4],'updated_nanos':state[5],'in_flight':state[6],
   'termination_reserved_ns':state[7],'verified_completions':state[8],'flow':None,
   'flow_snapshot':None,'freshness':None}
 if state[9]:
  value['flow']={'initial_credit_ns':str(signed(state[10],state[11])),
   'credited_refill_ns':state[12],'discarded_refill_ns':state[13],
   'booked_reservation_ns':state[14],'live_debited_cpu_ns':state[15],
   'settlement_residual_cpu_ns':state[16],'settled_full_cpu_ns':state[17],
   'settlement_discard_ns':state[18]}
 need(flow[0] in (0,1) and fresh[0] in (0,1),'Invalid optional diagnostic discriminant')
 if flow[0]:
  value['flow_snapshot']={'paid_cpu_debit_ns':flow[1],'remaining_paid_credit_ns':str(signed(flow[2],flow[3])),
   'unsettled_known_live_cpu_ns':flow[4],'initial_credit_ns':str(signed(flow[5],flow[6])),
   'credited_refill_ns':flow[7],'discarded_refill_ns':flow[8],'booked_reservation_ns':flow[9],
   'live_debited_cpu_ns':flow[10],'settlement_residual_cpu_ns':flow[11],'settled_full_cpu_ns':flow[12],
   'settlement_discard_ns':flow[13],'termination_reserved_ns':flow[14],'live_owners':flow[15],
   'stored_credit_ns':str(signed(state[2],state[3])),'balance_identity_verified':True}
 if fresh[0]:
  need(fresh[8] in (0,1),'Invalid projection eligibility')
  value['freshness']={'watermark_age_ns':fresh[1],'projected_credited_refill_ns':fresh[2],
   'projected_discarded_refill_ns':fresh[3],'projected_stored_credit_ns':str(signed(fresh[4],fresh[5])),
   'projected_paid_credit_ns':str(signed(fresh[6],fresh[7])),'projected_scalar_start_eligible':bool(fresh[8])}
 return value
