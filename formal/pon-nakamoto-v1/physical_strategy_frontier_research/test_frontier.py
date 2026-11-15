#!/usr/bin/env python3
import functools
import itertools
import json
import random
import unittest
from fractions import Fraction as F
from hashlib import sha256
from frontier import (BASE, baseline, ref, Arithmetic, AffineProducts,
                      FrontierPrepared, recognize_affine, witness_bytes)
from selector_policy import (CacheModel, optimal_cache, optimal_static_filter,
                             finite_penalty, lazy_expected_products,
                             cache_until_first_hit_expected_products,
                             finite_success_lower_bound)


def affine(a, b, c):
    return tuple((a+b*i+c*j) % ref.Q for i in range(8) for j in range(8))


def materials():
    return tuple(baseline.decode_task((BASE/'upstream/reference'/name).read_bytes())
                 for name in ('structured-a.bin','structured-b.bin'))


def fixture():
    return baseline.decode_fixture(
        (BASE/'upstream/reference/real_lottery_hit_p_1_64.expected.bin').read_bytes(),
        (BASE/'upstream/reference/real_lottery_hit_p_1_64.witness.bin').read_bytes())


class ExactArithmeticTests(unittest.TestCase):
    def test_all_512_original_affine_products_match_dense(self):
        a,b=materials();meter=Arithmetic();compiled=AffineProducts(a,b,meter)
        for i,k,j in itertools.product(range(8),repeat=3):
            self.assertEqual(compiled.product(i,k,j),ref.block_mul(a[i*8+k],b[k*8+j]))

    def test_general_affine_products_wrap_modulus(self):
        rng=random.Random(472941)
        a=tuple(affine(*(rng.randrange(ref.Q) for _ in range(3))) for _ in range(64))
        b=tuple(affine(*(rng.randrange(ref.Q) for _ in range(3))) for _ in range(64))
        compiled=AffineProducts(a,b,Arithmetic())
        for _ in range(50):
            i,k,j=(rng.randrange(8) for _ in range(3))
            self.assertEqual(compiled.product(i,k,j),ref.block_mul(a[i*8+k],b[k*8+j]))

    def test_exact_recognition_and_compilation_cost(self):
        a,b=materials();meter=Arithmetic();compiled=AffineProducts(a,b,meter)
        self.assertEqual(meter.snapshot(),{'multiplications':448,
            'additions_including_subtractions':8512,'field_equality_checks':8192,
            'recognition_words':8192})
        before=meter.snapshot();compiled.product(7,6,5);after=meter.snapshot()
        self.assertEqual(after['multiplications']-before['multiplications'],5)
        self.assertEqual(after['additions_including_subtractions']-before['additions_including_subtractions'],71)
        self.assertEqual(4*(sum(map(len,compiled.left))+sum(map(len,compiled.right))),2048)

    def test_nonaffine_word_is_refused(self):
        for index in (0,1,8,27,63):
            block=list(affine(100,22,45));block[index]=(block[index]+1)%ref.Q
            with self.assertRaisesRegex(ValueError,'NON_AFFINE_BLOCK'):
                recognize_affine(tuple(block),Arithmetic())

    def test_noncanonical_field_is_refused(self):
        for value in (-1,ref.Q,True):
            block=list(affine(10,20,30));block[63]=value
            with self.assertRaises(ref.Refusal):recognize_affine(tuple(block),Arithmetic())

    def test_zero_and_constant_affine_inputs_are_exact(self):
        a=tuple(affine(0,0,0) for _ in range(64))
        b=tuple(affine(8,0,0) for _ in range(64))
        self.assertEqual(AffineProducts(a,b,Arithmetic()).product(0,0,0),(0,)*64)
        c=tuple(affine(ref.Q-1,0,0) for _ in range(64))
        self.assertEqual(AffineProducts(c,c,Arithmetic()).product(1,2,3),(8,)*64)

    def test_original_witness_and_full_verifier_unchanged(self):
        a,b=materials();ctx,expected=fixture()
        for arithmetic in ('dense','affine'):
            for cache in ('none','eager','lazy'):
                producer=FrontierPrepared(a,b,arithmetic=arithmetic,cache=cache)
                observed=producer.produce(ctx,expected.nonce)
                self.assertEqual(witness_bytes(expected),witness_bytes(observed))
                self.assertEqual(ref.verify(ctx,observed),ref.verify(ctx,expected))

    def test_producers_match_original_unprepared_reference(self):
        a,b=materials();ctx,_=fixture();producer=FrontierPrepared(a,b,arithmetic='affine',cache='lazy')
        for nonce in (0,24,25,26):
            self.assertEqual(witness_bytes(producer.produce(ctx,nonce)),witness_bytes(ref.produce(ctx,nonce,a,b)))

    def test_lazy_capacity_and_every_miss_charged(self):
        a,b=materials();producer=FrontierPrepared(a,b,cache='lazy',capacity=2)
        stream=((0,0,0),(0,0,0),(0,0,1),(0,0,2),(0,0,2),(0,0,1))
        for i,k,j in stream:self.assertEqual(producer.useful(i,k,j),ref.block_mul(a[i*8+k],b[k*8+j]))
        state=producer.cache_record()
        self.assertEqual((state['lookups'],state['hits'],state['misses'],state['computed_useful_products'],state['entries']),
                         (6,2,4,4,2))
        self.assertEqual(state['cached_result_payload_bytes'],512)

    def test_unbounded_lazy_computes_each_observed_coordinate_once(self):
        a,b=materials();producer=FrontierPrepared(a,b,cache='lazy')
        stream=((0,0,0),(1,2,3),(1,2,3),(7,6,5),(0,0,0))
        for c in stream:producer.useful(*c)
        self.assertEqual(producer.computed_products,len(set(stream)))

    def test_wrong_task_root_is_refused(self):
        a,b=materials();ctx,_=fixture();producer=FrontierPrepared(a,b,arithmetic='affine')
        wrong=ref.Expected(ctx.chain,ctx.parent,ctx.header_without_work,bytes(32),ctx.root_b,ctx.target)
        with self.assertRaisesRegex(ValueError,'TASK_ROOT'):producer.produce(wrong,0)

    def test_frozen_upstream_digests(self):
        manifest=json.loads((BASE/'UPSTREAM_SOURCE.json').read_text())
        for name,digest in manifest['files'].items():
            self.assertEqual(sha256((BASE/'upstream'/name).read_bytes()).hexdigest(),digest)


class PolicyTests(unittest.TestCase):
    def test_expected_distinct_formula_by_enumeration(self):
        for d,n in ((1,5),(2,4),(3,3),(4,4)):
            total=sum(len(set(seq)) for seq in itertools.product(range(d),repeat=n))
            self.assertEqual(lazy_expected_products(n,d),F(total,d**n))

    def test_first_hit_cache_formula_edge_cases(self):
        self.assertEqual(cache_until_first_hit_expected_products(512,F(1,64)),F(32768,575))
        self.assertEqual(cache_until_first_hit_expected_products(1,F(1,64)),1)
        self.assertEqual(cache_until_first_hit_expected_products(512,1),1)

    def test_static_filter_matches_all_nonempty_subsets(self):
        for costs in ((1,2,20),(0,4,9,30),(3,3,3,3),(100,1,2,8,50)):
            g,p=F(3,2),F(1,8)
            result=optimal_static_filter(g,costs,p)
            values=[]
            for bits in itertools.product((0,1),repeat=len(costs)):
                selected=[c for c,b in zip(costs,bits) if b]
                if selected:values.append((len(costs)*g+sum(selected))/(len(selected)*p))
            self.assertEqual(result['value'],min(values))

    def test_cached_bellman_matches_exhaustive_stationary_policies(self):
        # Separate policy enumeration, with direct transition equations.
        for useful,insertion in ((8,0),(1,100),(20,3)):
            m=CacheModel(3,2,F(1,4),F(2),F(5),F(useful),F(1),F(insertion))
            action_sets=[list(itertools.product((0,1),(0,1,2))) for _ in range(2)]
            action_sets.append(list(itertools.product((0,1),(0,1))))
            answers=[]
            for policy in itertools.product(*action_sets):
                values=[None]*3
                for k in (2,1,0):
                    h,a=policy[k];ph=F(k,3);pm=1-ph
                    charge=F(3)+ph*h*5
                    loop=ph*(1-F(h,4))
                    if a==0:loop+=pm
                    elif a==1:
                        charge+=pm*(5+useful);loop+=pm*F(3,4)
                    else:
                        if values[k+1] is None:continue
                        charge+=pm*(5+useful+insertion+F(3,4)*values[k+1])
                    if loop<1:values[k]=charge/(1-loop)
                if values[0] is not None:answers.append(values[0])
            self.assertEqual(optimal_cache(m)[0]['value'],min(answers))

    def test_finite_dp_matches_coordinate_level_history_search(self):
        d,cap,p,g,c,u,ins,lookup=3,2,F(1,4),F(2),F(5),F(8),F(1),F(1)
        m=CacheModel(d,cap,p,g,c,u,lookup,ins)
        penalty=F(70)
        @functools.lru_cache(None)
        def exhaustive(n,held):
            if not n:return penalty
            kept=set(held);continuation=F(0)
            for coordinate in range(d):
                stay=exhaustive(n-1,held)
                options=[stay,c+(0 if coordinate in kept else u)+(1-p)*stay]
                if coordinate not in kept and len(kept)<cap:
                    future=exhaustive(n-1,tuple(sorted(kept|{coordinate})))
                    options.append(c+u+ins+(1-p)*future)
                continuation+=min(options)/d
            return min(penalty,g+lookup+continuation)
        for n in range(6):
            result=finite_penalty(m,n,penalty)
            for k in range(cap+1):self.assertEqual(result[k]['value'],exhaustive(n,tuple(range(k))))

    def test_resource_budget_monotonicity(self):
        values=[optimal_cache(CacheModel(32,k,F(1,8),F(3),F(14),F(80)))[0]['value'] for k in (0,1,2,4,8,16,32)]
        self.assertEqual(values,sorted(values,reverse=True))

    def test_no_useful_cost_needs_no_filter(self):
        for cap in (0,1,8):
            value=optimal_cache(CacheModel(8,cap,F(1,4),F(3),F(7),F(0)))[0]['value']
            self.assertEqual(value,40)

    def test_excessive_insertion_avoids_storage(self):
        result=optimal_cache(CacheModel(8,8,F(1,8),F(3),F(7),F(2),insertion=F(10000)))
        self.assertEqual(result[0]['value'],96)
        self.assertEqual(result[0]['miss'],'attempt')

    def test_declared_512_coordinate_optimum_threshold(self):
        states=optimal_cache(CacheModel(512,16,F(1,64),F(3),F(1580),F(512)))
        self.assertTrue(all(x['miss']=='store' for x in states[:15]))
        self.assertEqual(states[15]['miss'],'skip')
        self.assertLess(states[0]['value'],F(134080))

    def test_finite_objective_keeps_failure_separate(self):
        result=finite_penalty(CacheModel(512,16,F(1,64),F(3),F(1580),F(512)),1,F(250000))[0]
        self.assertEqual(result['cost'],2095)
        self.assertEqual(result['failure'],F(63,64))
        self.assertEqual(result['value'],result['cost']+250000*result['failure'])

    def test_finite_success_dual_is_sharp_in_two_trial_case(self):
        # No cache or useful surcharge. Each paid attempt costs two units.
        # Two iid p=1/2 attempts, stop on success: E[cost]=3, success=3/4.
        # Any policy meeting 3/4 must attempt after the first failure;
        # the lambda=4 weak-dual certificate independently attains three.
        model=CacheModel(2,0,F(1,2),F(1),F(1),F(0))
        bound=finite_success_lower_bound(model,2,F(3,4),F(4))
        self.assertEqual(bound['cost_lower_bound'],3)
        self.assertEqual(bound['penalized_optimum'],4)
        self.assertEqual(finite_success_lower_bound(model,0,F(0),F(4))['cost_lower_bound'],0)
        for alpha in (-1,2):
            with self.assertRaises(ValueError):finite_success_lower_bound(model,2,alpha,F(4))

    def test_invalid_models_refused(self):
        for m in (CacheModel(0,0,F(1,2),F(1),F(1),F(1)),
                  CacheModel(3,4,F(1,2),F(1),F(1),F(1)),
                  CacheModel(3,2,F(0),F(1),F(1),F(1)),
                  CacheModel(3,2,F(1,2),F(0),F(1),F(1)),
                  CacheModel(3,2,F(1,2),F(1),F(-1),F(1))):
            with self.assertRaises(ValueError):optimal_cache(m)

if __name__=='__main__':unittest.main(verbosity=2)
