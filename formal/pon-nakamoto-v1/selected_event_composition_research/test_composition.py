#!/usr/bin/env python3
"""Reconstructed checks. Counts and outcomes come only from a fresh execution."""
import itertools
import json
from collections import Counter
from fractions import Fraction
from hashlib import sha256
import unittest
from composition_budget import (beta,hash_exception,binomial_tail,evaluate,
    noise_abort_probability,product_counts,amortized_arithmetic,Resources)
from exact_cost import (BASE,ref,encode,decode_hash,sha_blocks,Recorder,Prepared,
    hash_length_table,observe_fixtures,producer_campaign)
from sha256_prefix import PrefixSHA256,BoundedPrefixSHA256,pad
from transcript_audit import Audit

class EncodingChecks(unittest.TestCase):
    def test_recovered_reference_pins(self):
        for name,entry in json.loads((BASE/'provenance.json').read_text())['source_files'].items():
            self.assertEqual(sha256((BASE/'reference'/name).read_bytes()).hexdigest(),entry['sha256'])

    def test_framing_roundtrip_injectivity(self):
        seen={};atoms=(b'',b'a',b'bc',b'a\x00',b'\x00\x01')
        for tag in (b'',b'x',b'event',b'noise-eight'):
            for n in range(4):
                for parts in itertools.product(atoms,repeat=n):
                    m=encode(tag,*parts);self.assertEqual(decode_hash(m),(tag,parts))
                    if m in seen:self.assertEqual(seen[m],(tag,parts))
                    seen[m]=(tag,parts)
        self.assertNotEqual(encode(b'x',b'a',b'bc'),encode(b'x',b'ab',b'c'))
        self.assertNotEqual(encode(b'x'),encode(b'x',b''))

    def test_exact_hash_lengths(self):
        table=hash_length_table()
        self.assertEqual([(v['input_bytes'],v['full_sha256_compressions']) for v in table.values()],
                         [(361,6),(173,3),(163,3),(274,5),(95,2),(92,2),(98,2),(617,10),(79,2)])
        self.assertEqual((len(ref.DOMAIN),len(ref.PROFILE)),(36,46))

    def test_selected_rows_distinct_all_coordinates(self):
        for bi,bk,bj in itertools.product(range(8),repeat=3):
            rows=[(0,bi*8+i) for i in range(8)]+[(1,i*8+bk) for i in range(8)]
            rows += [(2,bk*8+i) for i in range(8)]+[(3,i*8+bj) for i in range(8)]
            self.assertEqual(len(set(rows)),32)
        self.assertEqual(set(Counter(x&7 for x in range(256)).values()),{32})

class ProbabilityChecks(unittest.TestCase):
    def test_missing_row_exhaustive_scalar_analogue(self):
        for a,b in itertools.product(range(2),repeat=2):
            for missing in range(4):
                buckets={}
                for factors in itertools.product(range(2),repeat=4):
                    x,y,z,t=factors;d=((a+x*y)*(b+z*t))%2
                    side=factors[:missing]+factors[missing+1:]
                    buckets.setdefault(side,Counter())[d]+=1
                best=Fraction(sum(max(v.values()) for v in buckets.values()),16)
                self.assertLessEqual(best,beta(2,1))
                if a==b==0:self.assertEqual(best,Fraction(15,16))

    def test_adaptive_equality_uses_coverage(self):
        support=set(range(4))
        self.assertGreater(Fraction(1,len(support-{0})),Fraction(1,len(support)))
        for guesses in itertools.permutations(range(4),2):
            self.assertEqual(Fraction(len(set(guesses)),4),Fraction(1,2))

    def test_toy_reverse_pointer_probability(self):
        n=4;guessed={0,2};draws=3
        hits=sum(any(v in guessed for v in outputs) for outputs in itertools.product(range(n),repeat=draws))
        actual=Fraction(hits,n**draws)
        self.assertEqual(actual,1-(1-Fraction(len(guessed),n))**draws)
        self.assertLessEqual(actual,Fraction(draws*len(guessed),n))

    def test_typed_hash_budget(self):
        caps={'leaf':8,'node':7,'task':2,'context':3,'noise-seed':5,'selected-coordinate':5,
              'noise-eight':160,'event':10,'ticket':11,'other':4}
        result=hash_exception(caps);terms=result['numerator_terms'];q=sum(caps.values())
        self.assertEqual(terms['event_reverse_pointers'],110)
        self.assertEqual(terms['seed_reverse_pointers'],825)
        self.assertEqual(terms['merkle_reverse_pointers'],270)
        self.assertLessEqual(result['probability'],Fraction(5*q*q,2*2**256))

    def test_completion_never_gives_miner_H(self):
        config={'candidate_pair_cap_M':2,'early_event_guesses_per_pair_cap_R':1,
                'adversary_distinct_row_access_cap_H':31,'target_hex':'03'+'ff'*31,
                'adversary_query_caps':{'noise-seed':2,'noise-eight':31,'event':2,'ticket':2}}
        before=evaluate(config);config['completion_query_caps']={'noise-eight':64,'event':2,'ticket':2}
        after=evaluate(config)
        self.assertEqual(before['paid_first_trial_cap_K'],0);self.assertEqual(after['paid_first_trial_cap_K'],0)
        self.assertEqual(after['total_lifetime_query_cap_Q']-before['total_lifetime_query_cap_Q'],68)

    def test_exact_lottery_threshold(self):
        p=Fraction(1,64)
        self.assertLess(binomial_tail(44,p),Fraction(1,2));self.assertGreater(binomial_tail(45,p),Fraction(1,2))
        self.assertEqual(binomial_tail(3,p,2),3*p*p*(1-p)+p**3)
        self.assertEqual(binomial_tail(0,p),0)

    def test_rejection_sampling_distribution(self):
        self.assertEqual(noise_abort_probability(1),1-Fraction(ref.Q,2**32)**8)
        counts=Counter()
        for raw in itertools.product(range(4),repeat=3):
            accepted=[v for v in raw if v<3]
            if len(accepted)>=2:counts[tuple(accepted[:2])]+=1
        self.assertEqual(len(counts),9);self.assertEqual(len(set(counts.values())),1)

class TranscriptChecks(unittest.TestCase):
    def test_event_prequery_without_output_collision(self):
        audit=Audit();guess=(1).to_bytes(32,'big')
        self.assertEqual(audit.add(encode(b'ticket',guess),bytes(32)),[])
        message=encode(b'event',bytes(32),bytes(8),bytes(3),bytes(256),bytes(256))
        self.assertEqual(audit.add(message,guess),['REVERSE_POINTER_EVENT'])

    def test_seed_prequery(self):
        audit=Audit();seed=(7).to_bytes(32,'big')
        audit.add(encode(b'noise-eight',seed,bytes(2),bytes(4)),(8).to_bytes(32,'big'))
        self.assertEqual(audit.add(encode(b'noise-seed',bytes(32),bytes(8)),seed),['REVERSE_POINTER_SEED'])

    def test_context_reversal_and_seed_alias(self):
        audit=Audit();ctx=(3).to_bytes(32,'big');seed=(4).to_bytes(32,'big')
        audit.add(encode(b'noise-seed',ctx,bytes(8)),seed)
        message=encode(b'context',ref.PROFILE,bytes(32),bytes(32),bytes(32),bytes(32),b'\xff'*32)
        self.assertIn('REVERSE_POINTER_CONTEXT',audit.add(message,ctx))
        self.assertIn('OUTPUT_COLLISION',audit.add(encode(b'noise-seed',ctx,(1).to_bytes(8,'little')),seed))

    def test_public_setup_belongs_in_lifetime_transcript(self):
        blocks=tuple(tuple((17*i+13*j)%ref.Q for j in range(64)) for i in range(64))
        preparation=Recorder()
        with preparation.active():task=Prepared(blocks,blocks)
        ctx=ref.Expected(bytes(32),bytes(32),bytes(32),task.ta[-1][0],task.tb[-1][0],b'\xff'*32)
        run=Recorder()
        with run.active():w=task.produce(ctx,0);ref.verify(ctx,w)
        complete=Audit()
        for m in preparation.messages+run.messages:complete.add(m,sha256(m).digest())
        self.assertEqual(complete.exceptions,[])
        partial=Audit()
        for m in run.messages:partial.add(m,sha256(m).digest())
        self.assertTrue(any('REVERSE_POINTER_MERKLE' in x['events'] for x in partial.exceptions))

class PricingChecks(unittest.TestCase):
    def test_compression_padding_and_repeat(self):
        engine=PrefixSHA256()
        for n in (0,1,55,56,63,64,65,119,120,255,617,1024):
            message=bytes((i*17)%256 for i in range(n))
            self.assertEqual(len(pad(message))//64,sha_blocks(n))
            self.assertEqual(engine.digest(message),sha256(message).digest())
        before=engine.compressions;self.assertEqual(engine.digest(message),sha256(message).digest())
        self.assertEqual(engine.compressions,before)

    def test_noise_prefix_64_to_33(self):
        seed=sha256(b'isolated compression test').digest()
        messages=[encode(b'noise-eight',seed,bytes([label,index]),bytes(4)) for label in range(4) for index in range(8)]
        self.assertEqual(sum(sha_blocks(len(v)) for v in messages),64)
        engine=PrefixSHA256()
        for m in messages:self.assertEqual(engine.digest(m),sha256(m).digest())
        self.assertEqual(engine.compressions,33)

    def test_bounded_cache_eviction(self):
        engine=BoundedPrefixSHA256()
        for i in range(100):
            seed=sha256(i.to_bytes(4,'little')).digest()
            for index in range(8):
                m=encode(b'noise-eight',seed,bytes([0,index]),bytes(4))
                self.assertEqual(engine.digest(m,'noise-eight'),sha256(m).digest())
        self.assertEqual(engine.compressions,900)
        self.assertEqual(engine.payload()['prefix_state_bytes'],32)
        self.assertEqual(engine.payload()['prefix_key_bytes'],64)

    def test_recovered_native_observation_replay(self):
        observed=observe_fixtures();self.assertEqual(len(observed),3)
        self.assertEqual(observed[0]['counts']['sha256_compression_blocks'],152)
        self.assertEqual(observed[1]['counts']['scalar_multiplications'],1536)
        self.assertEqual(observed[2]['counts']['scalar_multiplications'],2048)

    def test_prepared_producer_and_bounded_cache_schedule(self):
        direct=producer_campaign((24,25),False);cached=producer_campaign((24,25),True)
        self.assertEqual(direct['preparation_counts']['sha256_compression_blocks'],1146)
        self.assertEqual(direct['preparation_prefix_cached_compressions'],894)
        self.assertEqual(cached['preparation_counts']['scalar_multiplications'],262144)
        for i,(a,b) in enumerate(zip(direct['trials'],cached['trials'])):
            self.assertEqual(a['event_id'],b['event_id']);self.assertEqual(a['ticket'],b['ticket'])
            self.assertEqual(a['counts']['scalar_multiplications'],2048)
            self.assertEqual(b['counts']['scalar_multiplications'],1536)
            self.assertEqual(a['counts']['sha256_compression_blocks'],96)
            self.assertEqual(a['prefix_cached_new_compressions'],57 if i==0 else 47)
            self.assertEqual(a['bounded_cache_new_compressions'],57 if i==0 else 47)
        self.assertEqual(sum(v for k,v in direct['final_bounded_cache_payload'].items() if k.endswith('_bytes')),981)

    def test_arithmetic_prices_and_amortization(self):
        self.assertEqual([product_counts(i).field_multiplications for i in range(4)],[512,448,392,343])
        self.assertEqual([product_counts(i).field_additions for i in range(4)],[448,624,988,1674])
        for n in (0,1,511,512,513,1000):
            direct=amortized_arithmetic(n,cache_useful=False);cached=amortized_arithmetic(n,cache_useful=True)
            self.assertEqual(cached.field_multiplications-direct.field_multiplications,262144-512*n)
        self.assertEqual(Resources(sha_compressions=33,field_multiplications=7).priced(
            {'sha_compressions':'3/2','field_multiplications':2}),Fraction(127,2))

if __name__=='__main__':unittest.main(verbosity=2)
