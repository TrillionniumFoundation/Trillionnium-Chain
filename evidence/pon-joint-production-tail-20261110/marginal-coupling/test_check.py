from fractions import Fraction as F
from itertools import permutations,product
import unittest
from check import product_extrema

class CouplingTests(unittest.TestCase):
    def test_independent_exhaustive_assignment(self):
        # Each permutation is an extreme doubly stochastic coupling (uniform atoms).
        # No greedy coupling algorithm is used by this oracle.
        for n in range(1,6):
            for shift in range(3):
                u=[F((i*7+shift*3)%11+1,3) for i in range(n)]
                h=[F((i*5+shift)%13+1,5) for i in range(n)]
                all_values=[sum((u[i]*h[j] for i,j in enumerate(p)),F())/n for p in permutations(range(n))]
                r=product_extrema([(x,F(1,n)) for x in u],[(x,F(1,n)) for x in h])
                self.assertEqual(r['upper'],max(all_values));self.assertEqual(r['lower'],min(all_values))
    def test_nonuniform_transportation_independent_2x2(self):
        # Exact feasible endpoint interval for cell (0,0); objective is affine.
        for p,q in product([F(1,5),F(1,2),F(4,5)],repeat=2):
            u=[F(1,3),F(7,3)];h=[F(1,4),F(3,4)]
            def objective(x):return x*u[0]*h[0]+(p-x)*u[0]*h[1]+(q-x)*u[1]*h[0]+(1-p-q+x)*u[1]*h[1]
            endpoints=[objective(max(F(0),p+q-1)),objective(min(p,q))]
            r=product_extrema([(u[0],p),(u[1],1-p)],[(h[0],q),(h[1],1-q)])
            self.assertEqual((r['lower'],r['upper']),(min(endpoints),max(endpoints)))
    def test_cs_can_refuse_while_sharp_bound_passes(self):
        u=[(F(1,2),F(1,2)),(F(3,2),F(1,2))];h=[(F(9,10),F(1))]
        r=product_extrema(u,h)
        self.assertEqual(r['upper'],F(9,10))
        self.assertEqual(sum(p*v*v for v,p in u)*sum(p*v*v for v,p in h),F(81,80))
    def test_product_of_means_can_falsely_pass(self):
        u=[(F(1),F(3,5)),(F(2),F(2,5))];h=[(F(1,2),F(3,5)),(F(1),F(2,5))]
        self.assertEqual(sum(p*v for v,p in u)*sum(p*v for v,p in h),F(49,50))
        self.assertEqual(product_extrema(u,h)['upper'],F(11,10))
    def test_plans_preserve_both_marginals(self):
        u=[(F(1),F(2,3)),(F(4),F(1,3))];h=[(F(1,4),F(1,4)),(F(1,2),F(3,4))]
        r=product_extrema(u,h)
        for key in ['lower_plan','upper_plan']:
            for value,mass in u:self.assertEqual(sum(p for x,y,p in r[key] if x==value),mass)
            for value,mass in h:self.assertEqual(sum(p for x,y,p in r[key] if y==value),mass)
    def test_exact_rationals_and_mass_required(self):
        good=[(F(1),F(1))]
        for bad in [[(1,F(1))],[(F(1),0.5)],[(F(0),F(1))],[(F(1),F(1,2))],[]]:
            with self.assertRaises(ValueError):product_extrema(bad,good)
    def test_unknown_native_claims_remain_unknown(self):
        r=product_extrema([(F(1),F(1))],[(F(1),F(1))])
        self.assertIsNone(r['native_failure_bound']);self.assertFalse(r['production_activation'])

if __name__=='__main__':unittest.main()
