"""Non-activated ASERT metamorphic/property testing; never a consensus acceptance receipt."""
import random, unittest
from daa_research_oracle import asert_target
CAP=(1<<255)-1
class AsertMetamorphicAudit(unittest.TestCase):
 def test_timestamp_monotonicity(self):
  rng=random.Random(20261025)
  for _ in range(2500):
   target=1<<rng.randint(10,245); height=rng.randint(2,5000); spacing=rng.choice((1,10,60,600)); half_life=rng.choice((3600,7200,14400,28800)); before=rng.randint(500000,1000000); now=before+rng.randint(0,200000)
   a=asert_target(target,before,now,1,height,spacing,half_life,CAP)
   b=asert_target(target,before,now+1,1,height,spacing,half_life,CAP)
   self.assertLessEqual(a,b)
 def test_extra_block_increases_difficulty_at_equal_time(self):
  rng=random.Random(20261026)
  for _ in range(2500):
   target=1<<rng.randint(10,245); height=rng.randint(2,5000); before=rng.randint(500000,1000000); now=before+rng.randint(0,200000)
   a=asert_target(target,before,now,1,height,10,7200,CAP)
   b=asert_target(target,before,now,1,height+1,10,7200,CAP)
   self.assertGreaterEqual(a,b)
 def test_no_exceptions_for_valid_wide_stress(self):
  extreme=(0,1,2**32,2**63,2**64-1)
  for before in extreme:
   for after in extreme:
    for height in (2,3,65536,2**32,2**64-1):
     for hl in (1,3600,2**64-1):
      try: result=asert_target(1<<128,before,after,1,height,10,hl,CAP)
      except ValueError: continue
      self.assertTrue(1<=result<=CAP)
if __name__=='__main__':unittest.main()
