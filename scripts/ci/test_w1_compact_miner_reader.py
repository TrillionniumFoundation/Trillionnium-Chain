#!/usr/bin/env python3
"""Compact binary grammar controls; synthetic zero-work fixtures are not native evidence.

The full reader invokes the unchanged scalar oracle. These fast controls do not
claim a new native execution, measured yield, or any proof of physical cost.
"""
from __future__ import annotations
import copy
import gzip
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import w1_compact_miner_reader as c


def stamp(n):
    return dict(process_cpu_ns=n, wall_ns=2*n)


def frame(tag, payload):
    if type(payload) is dict:
        payload = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()
    return struct.pack('<BI', tag, len(payload)) + payload


def synthetic_zero_work_rows():
    """Parser-only P=0 grammar fixture, explicitly not an observed native run."""
    options = c.options_from_args(['--setup-budget-ns', '0'])
    start = dict(schema=c.SCHEMA, options=options, origin=stamp(0), phase_order=list(c.PHASES),
        cpu_scope='actual-process-CPU-no-observer-subtraction', winner_payload='unchanged-Packet-encode',
        packet_bytes=c.PACKET_BYTES, miss_originals_retained=False, trace_commitment_is_paid_observation=True,
        commitment_required_by_consensus=False, trace_kernel='DeferredPrepared-integer-paired-general',
        production_activation=False, minimum_attacker_cost_established=False)
    def boundary(old, new, begin, end):
        return (c.BOUNDARY, {
            'from':old, 'to':new, 'begin':stamp(begin), 'end':stamp(end),
            'elapsed_cpu_ns':end-begin, 'boundary_output_charged_to_next_phase':True})
    seal = dict(setup_complete=False, stop_reason='setup-incomplete', attempts=0, target_hits=0,
        target_misses=0, attempts_available_by_b=0, full_winners_available_by_b=0, trace_commitment=None,
        committed_attempt_payload_bytes=0, winner_packet_bytes=0, original_miss_records=0,
        first_attempt_begin=None, last_attempt_begin=None, last_attempt_available=None,
        last_attempt_accounted=None, stop_poll=stamp(110),
        availability_to_accounting_observation_cpu_ns=0, availability_to_accounting_observation_wall_ns=0)
    audit = dict(research_recomputed=0, setup_recomputed=0, research_hits=0, research_misses=0,
        trace_commitment=None, reference_relation_checks=0, posthoc_miss_bytes_are_original=False,
        posthoc_new_credit=0, feedback_to_miner=False, observed=stamp(170))
    end = dict(schema=c.SCHEMA, status='PASS', setup_complete=False, attempts=0, target_misses=0,
        target_hits=0, attempts_available_by_B=0, full_winners_available_by_B=0,
        native_accepted=0, native_accepted_from_B=0, late_attempts=0, late_winners=0,
        censored_by_attempt_cap=False, phase_cpu_ns=dict(setup=100,miner=40,receiver=20,audit=20),
        post_stop_seal_cpu_ns=30, native_total_endpoint=stamp(200), candidate_chain_activation=False,
        minimum_attacker_cost_established=False, production_activation=False,
        final_serialization_and_remaining_drops_in_whole_child_residual=True)
    return [(c.START,start),boundary('setup','miner',0,100),(c.SEAL,seal),
        boundary('miner','receiver',100,140),boundary('receiver','audit',140,160),
        (c.AUDIT,audit),boundary('audit','done',160,180),(c.END,end)]


def encode_rows(rows):
    return c.MAGIC + b''.join(frame(tag, value) for tag, value in rows)


class CompactReaderControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='w1-compact-reader-unit-')
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'fixture.bin'

    def read_bytes(self, raw):
        self.path.write_bytes(raw)
        return c.read_compact(self.path)

    def reject_mutation(self, mutate, label):
        rows = copy.deepcopy(synthetic_zero_work_rows())
        mutate(rows)
        with self.assertRaisesRegex((ValueError, TypeError), label):
            self.read_bytes(encode_rows(rows))

    def test_synthetic_zero_work_only_checks_grammar_and_no_scalar_work(self):
        raw = encode_rows(synthetic_zero_work_rows())
        result = self.read_bytes(raw)
        self.assertFalse(result['setup_complete'])
        self.assertEqual(result['full_proof_records_replayed'], 0)
        self.assertEqual(result['deterministic_attempts_recomputed'], 0)
        self.assertEqual(result['raw_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result['total_process_cpu_ns'], 200)
        self.assertEqual(sum(result['phase_cpu_ns'].values()), 180)
        self.assertFalse(result['physical_or_clock_attestation'])

    def test_gzip_is_same_original_stream(self):
        raw = encode_rows(synthetic_zero_work_rows())
        path = Path(self.tmp.name) / 'fixture.gz'
        path.write_bytes(gzip.compress(raw, mtime=0))
        result = c.read_compact(path)
        self.assertEqual(result['raw_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result['raw_bytes'], len(raw))

    def test_wrong_magic(self):
        with self.assertRaisesRegex(ValueError, 'COMPACT_MAGIC'):
            self.read_bytes(b'INVALID!' + encode_rows(synthetic_zero_work_rows())[8:])

    def test_truncated_magic(self):
        with self.assertRaisesRegex(ValueError, 'TRUNCATED_MAGIC'):
            self.read_bytes(c.MAGIC[:-1])

    def test_truncated_last_payload(self):
        with self.assertRaisesRegex(ValueError, 'TRUNCATED_FRAME'):
            self.read_bytes(encode_rows(synthetic_zero_work_rows())[:-1])

    def test_trailing_byte(self):
        with self.assertRaisesRegex(ValueError, 'TRUNCATED_FRAME'):
            self.read_bytes(encode_rows(synthetic_zero_work_rows()) + b'\0')

    def test_trailing_complete_frame(self):
        with self.assertRaisesRegex(ValueError, 'TRAILING_FRAME'):
            self.read_bytes(encode_rows(synthetic_zero_work_rows()) + frame(c.END, synthetic_zero_work_rows()[-1][1]))

    def test_oversized_declared_length_before_payload(self):
        with self.assertRaisesRegex(ValueError, 'FRAME_LENGTH'):
            self.read_bytes(c.MAGIC + struct.pack('<BI', c.START, c.FRAME_LIMIT + 1))

    def test_zero_length_frame(self):
        with self.assertRaisesRegex(ValueError, 'FRAME_LENGTH'):
            self.read_bytes(c.MAGIC + struct.pack('<BI', c.START, 0))

    def test_unknown_tag(self):
        with self.assertRaisesRegex(ValueError, 'FRAME_TAG'):
            self.read_bytes(c.MAGIC + frame(255, b'{}'))

    def test_duplicate_json_key(self):
        rows = synthetic_zero_work_rows()
        payload = json.dumps(rows[0][1]).encode()
        payload = b'{"schema":"wrong",' + payload[1:]
        with self.assertRaises(ValueError):
            self.read_bytes(c.MAGIC + frame(c.START, payload))

    def test_unknown_json_field(self):
        self.reject_mutation(lambda rows: rows[0][1].update(hidden=True), 'FRAME_FIELDS')

    def test_start_bool_zero_alias(self):
        self.reject_mutation(lambda rows: rows[0][1]['origin'].update(process_cpu_ns=False), 'START_CLAIMS')

    def test_boundary_bool_zero_alias(self):
        self.reject_mutation(lambda rows: rows[1][1]['begin'].update(process_cpu_ns=False), 'CPU_STAMP')

    def test_boundary_float_duration_alias(self):
        self.reject_mutation(lambda rows: rows[1][1].update(elapsed_cpu_ns=100.0), 'PHASE_CPU')

    def test_miss_counter_float_alias(self):
        self.reject_mutation(lambda rows: rows[2][1].update(target_misses=0.0), 'SEAL_COUNT')

    def test_unpaid_miss_counter_not_accepted(self):
        self.reject_mutation(lambda rows: rows[2][1].update(target_misses=1), 'ALL_FAILURES_COUNTED')

    def test_zero_setup_cannot_be_claimed_complete(self):
        self.reject_mutation(lambda rows: rows[2][1].update(setup_complete=True), 'SEAL_SETUP')

    def test_incomplete_setup_cannot_claim_trace_commitment(self):
        self.reject_mutation(lambda rows: rows[2][1].update(trace_commitment='00'*32), 'INCOMPLETE_SETUP_NO_MINING')

    def test_missing_seal(self):
        rows = synthetic_zero_work_rows(); del rows[2]
        with self.assertRaisesRegex(ValueError, 'MINER_SEAL_REQUIRED'):
            self.read_bytes(encode_rows(rows))

    def test_false_post_stop_cost(self):
        self.reject_mutation(lambda rows: rows[-1][1].update(post_stop_seal_cpu_ns=29), 'END_RECONCILIATION')

    def test_endpoint_before_audit_end(self):
        self.reject_mutation(lambda rows: rows[-1][1].update(native_total_endpoint=stamp(179)), 'TOTAL_ENDPOINT')

    def test_posthoc_credit_float_alias(self):
        self.reject_mutation(lambda rows: rows[5][1].update(posthoc_new_credit=0.0), 'AUDIT_RECONCILIATION')

    def test_production_activation_cannot_be_claimed(self):
        self.reject_mutation(lambda rows: rows[-1][1].update(production_activation=True), 'END_RECONCILIATION')

    def test_bad_options(self):
        for args in (['--seed','1','--seed','2'],['--seed','+1'],['--seed','4294967296'],
                     ['--miner-budget-ns','-1'],['--max-attempts','0'],['--max-attempts','4097'],
                     ['--unknown','1'],['--mode','compact'],['--seed','１']):
            with self.subTest(args=args), self.assertRaises(ValueError):
                c.options_from_args(args)

    def test_bool_option_alias(self):
        options = c.options_from_args([]); options['seed'] = True
        with self.assertRaises(ValueError): c.validate_options(options)

    def test_real_packet_length_is_not_compact_fake_proof(self):
        for raw in (bytes(c.PACKET_BYTES-1),bytes(c.PACKET_BYTES+1),bytes(32)):
            with self.assertRaisesRegex(ValueError,'NATIVE_PACKET_LENGTH'):
                c.packet_statement(raw,'00'*32)

    def test_nonempty_transaction_count_rejected(self):
        raw = bytearray(c.PACKET_BYTES); raw[c.HEADER_BYTES] = 1
        with self.assertRaisesRegex(ValueError,'NATIVE_EMPTY_TRANSACTIONS'):
            c.packet_statement(bytes(raw),'00'*32)

    def test_cap_and_budget_stop_are_distinct(self):
        options = c.options_from_args(['--max-attempts','1','--miner-budget-ns','10'])
        seal = copy.deepcopy(synthetic_zero_work_rows()[2][1])
        seal.update(setup_complete=True,stop_reason='safety-cap-censored',attempts=1,target_misses=1,
            attempts_available_by_b=0,trace_commitment='00'*32,committed_attempt_payload_bytes=40,
            first_attempt_begin=stamp(105),last_attempt_begin=stamp(105),
            last_attempt_available=stamp(111),last_attempt_accounted=stamp(112),stop_poll=stamp(113),
            availability_to_accounting_observation_cpu_ns=1,availability_to_accounting_observation_wall_ns=2)
        c.check_seal(seal,options,True,stamp(100),0)
        seal['stop_reason']='miner-cpu-budget-stopped'
        with self.assertRaisesRegex(ValueError,'STOP_REASON'):
            c.check_seal(seal,options,True,stamp(100),0)

    def test_late_attempt_cannot_be_backdated(self):
        options = c.options_from_args(['--miner-budget-ns','10'])
        seal = copy.deepcopy(synthetic_zero_work_rows()[2][1])
        seal.update(setup_complete=True,stop_reason='miner-cpu-budget-stopped',attempts=1,target_misses=1,
            attempts_available_by_b=1,trace_commitment='00'*32,committed_attempt_payload_bytes=40,
            first_attempt_begin=stamp(105),last_attempt_begin=stamp(105),
            last_attempt_available=stamp(111),last_attempt_accounted=stamp(112),stop_poll=stamp(113),
            availability_to_accounting_observation_cpu_ns=1,availability_to_accounting_observation_wall_ns=2)
        with self.assertRaisesRegex(ValueError,'BY_B_PREFIX'):
            c.check_seal(seal,options,True,stamp(100),0)

    def test_miner_zero_budget_starts_no_trial(self):
        options=c.options_from_args(['--miner-budget-ns','0'])
        seal=copy.deepcopy(synthetic_zero_work_rows()[2][1])
        seal.update(setup_complete=True,stop_reason='miner-cpu-budget-stopped',trace_commitment='00'*32)
        c.check_seal(seal,options,True,stamp(100),0)

# Original bytes from unfrozen small-cap functionality only. No performance
# inference. Each native source/binary/argv/raw identity is retained in origin.json.
REAL_FIXTURE_ARCHIVE_SHA256 = '55fa9607af8d00415739d864166b3438e697e3f8d346f84730870af3b7d76b35'
REAL_FIXTURE_ARCHIVE_B85 = r"""
{Wp48S^xk9=GL@E0stWa8~^|S5YJf5<;VX!NL>IooQYNVTyr(fnB)Z#t01dq+(n%5EUi7JgbeNt1gC@^#uccBYWB0NW2q~fz@%<c
0lCzYi{f14rn9pMx25EJ#<RRy0S7f$dkZL>`YP0`pTxz&98rkMUB|})wYLnp-
>ld7osEZU246gJSQy$#u7{bmh<Q<n2AopqPTecKF3SC!*fiaQ%6Q_ja{t7w5Y5ZZ)eRa;CYnj?FvH;n6i$oMqtE_JixRv<t!f`;f
=yDMBZKhw{WfQ53Bhj#xwv2wN~d9iS!vI)H2!_a7skPn<N$f+y`3K(-
1G1XF#>mE(mI9S@iyAZ1swWv_+G+{yEfp3(sW)W@2aqxWW@Bj&bXj4SlJ!jJU!3lTW@e^jtgGQ4y>d&Zrwa-rgW5`N5fUE;Nm9;l
cC{oHBs7@Rdd9OMPC8kW8j)lW85#;#-
(j+sHc!(5th3un2c<eI||covEK|CRD4XU@>E{*Lp=mc8g{CtMF>}#0*@^gPhcx2J0`$GK9u&SgApL%X-
zEasS)!&$#`z@PhpH{mYz<~j%Fr2i_)v+9MlR~pwuIwZISEShP`DPmrI-KJpA(+;%pbpIR#d`idFF*L5)m|1Z8j)=7=lQlRS=Z%e
uT=P!q^*rLZNVuQ45OJg1xg*SN1#!C5pl#MnG;wZos2&KMeVIM@_-
^$jxni$6IdU9sYxRMpa=225p_Vj(ha)ZuunB(H={^8)C;*@4S((o+tg(lfeqxmynGypAlvN$J;jPLad)j$0&Y{`_276rcex2KT?)
O*KR(7XAbTag`falZnuv93Z>zzPqa3?Pm-AgA1wgg%sVj{~MEe9Qi!|9Br%Vp==((I>ePDtyK!9B5twlU2NoLO|$5Ljdz=MP~Ckb
mdhd}-
3TqOWR(Jkt3{E}2I(FhF~e&gCq8aq+Phqem4I6DC@||%?0ZZYf!E3^TaB>D_^)(#w#hUhWu+5#gFK6Pq0WR(5;|uQoS`Z*{z?vdZ
L|s=eFkZ@1@%U3U>J#R4i}bocGbhY=P=>1^OmwYx9;<g6fCxN1_*g?@`g-
b`VDPU6#cgb;~y6oncoppys$+B%4qZ;<uI@Qu%O^?o9bgZjP@yhsRM`|o~uNQ8y#a{;*5V}Axd!o-
1LE3s_D&!&QA`@{w<HO8Oih&Z{o5HDIJi<P%Ohhc$LUW!~QL#O%tmD1u2d^Zq#A=l7LMnd^WN~1WlE6{hD*nu`5K;ukLbdR2~Q0b
=L(yh{&Q{HNY3GK6hQH*61QUZi>>x?;+!Gk9cg#M(RSk{qz%YERemQ^^5JQj{bwV{}-
i9v}1{k#vt(3numJ^wGaRL3)|4`XEl1+#8^S^yMkuJDgQ^T$&{K1Px$RH%k1t3M6G}5eiKn;2PAXO_uNlbN-
_38`rk`v+pogX(zB#SW)0SXaEJTq94^&v=pyi>Pj6KCfd|1#9=ZC|!U7|(?ghJ(yfA%(+;mK6NOdv)^-
;M%G5u1GpokbfP>u7TNPNn>Z_uGetoleST*qZU*zo5HT9vXQO*fk<WQ|&#9A#EWju@H+mj_+s>)&^GpH3h453CMBXBd_><HY;8iv
|@_LqsauLseR%WV}A|RN?_-4XROg_X(W@12_Tdm()OzK1JcGo}!Z^KV5vv!DJ-8cl@1au<X$uaLDuoRm5L+^V~WVed%Mi62-
q;uHO+sDv;{-(T|%oZ={2@(wvb-vupl*!V^2!Oh#dp{5c*tXgU`p=+n57Tkx$Ji2xm3#D^s}fV0GukJ`OS5@qnZD>_Kx@hduTB^c
~DRMD#${xmxAeb0_yPtR!W8Gq@*>MCWbx{3l^46Zw&dJHsano<2Ys{B=Fh;j_u@xTz7?KS$*Xi0~=>Bu<Whc#{|n+w!{7j({`sTo
{wDCx8#yD10U5?x*ZOsDcO*Ksk*Jd9Z!y9tpqk`6&V2P*u}1^m5!{G!&6$zjb`PCr1lFj27U{;hA_QkTzcNzOC6OuO2&IWd;j&Yg
MoM)Xxzt9)=Ml}=z1+<5tSPSkxS*Wnes$t0rkJWB^f0-
WO3P<~&PypF+h^20T3HX=oO!G&Lk0`A{feK#sdL!gBr;bnlELZ8HH#R@@CIIahRt3s*-
Zx!YOtFIht<!iJr>lkME3MoFEGIlPj<|3Y}mTp2Tlp;V3wLk;ZOt1R8h24m$B{Lw@oJlVX9<QbVk^HR3;TeFf@UrV-
^B4$0J=(OEh(bHf-NreXfTm(904;y3hkiJ^JMV3--GPg;z|&&Ep)L0aQ~7`ybeMQ{l8-R7ow@=Xum*tmAwi8sAxIma1lRt-
^J(N*rJjH_$-$eLBg|*0)Gb;c-0Z5Kkc+x@4?T-
C22?$%gtY}xV0MVq12&X@AcmYMZl<4Y4*p_u63Jd5ygmx61EzG|+EF1iWnpUmftC{KgSL|FYk>19sh1!JMfOiy*P=9}0L2ujXH!^
3hybM2BWl_$<UAc_A1+Rg<})^BZFbedY#jv-B)|U;M?NY}Tp46q$;2O8qme0}Q)<F8Ynn$aX6-
N^&?ybFzG=G8w|8cNt$kKZx#e;R>bP3hBXsxZa0<bSjL;sy-rqqboU;%W?9Mgp%0t{!6_SM1MT~|=NB_qS+m5%4BX??ljzrI?hnh
iVev-T2E3?c>Ta&Kt-<&}-
6){Q6ga1uj)+CSKrZgO77cDYCfA*gD5HkJl7sgsKUDc)6LI5$!l93d6COR?^w<#T)O#R1YXn~H<Wv;!rA&lEA<5lWox2uS1h$Q0R
8AF6ztJDq0PrG)Fd5`;2vF^;uHu8CRG<7sLdbHLm%rC06wE=aQjqKibu6wo1MMU;aDMfW;WW$ok0vdzhLG&;zt7iov?&Xg6=OWvY
es$I-#6j?~055JDRNcP`Ju(&6AB+A+V9!ASAykCPMn*Y!<dViDv+#{FVEh=(HGSo<Bu-WLgw!Vrj|(_DK6yt!6f+_lgWzPVEmNll
rGHy9RY92r6xtP<c(|+?zF6d?C(-P1NCVrt0mC#Z6ew+0;MIKS`Yu)bb1{cVr3Nh=B|PK6ip8|7nT1JheVhUj{Ox@s466c<UK-
s>Q(SpyK0yDyrIf*;5gBVO!dRui)B8ejVc7i9D8=rXjH~*CY(sHqz%>Rb-zZsOenQQ2Bbi)f4`vnHCZy7DqB+v>a?b7CcT$Gwr(3
f<O57pChAT9{xhW~YV9e#YWUB~J@yZ9sKG$YoTK5=}KPB=`bsteIZ>hl2ov$YONsCJ8oWgE>H4ES=4p#?bkJxQ)FE6*`!ns0bm;x
`ZSBNEFDu0&=ROm?#XAox2^OS@PUoY#00>SC=$@0%5#_t>C5|Ks#KA`W=+GD#p@*rTgA7tSg8~F^ao@|ELr4@L@G<xX^5kWOX`=@
3^?dubWgO*Vg%SmLHPGX58lQ}b9G#F9+_vd<e&(!zHbX<x!xsfBY-c6^b{`dZO?{&OlfU)9mcBL!<;J@X%ib2}I`OPjT-
LUyC%|!=uME`#@*R}5=*M0jWP-MS0_v;&~KTR<F$=^j_WFQ(g`DDsCaXCEdu?se<;6R0xV3hV`zPBJnCxKvku&4b%MQ<FyJP=G*q
yn3ztKGL?(9B>=Y$_tPze;DA$~T5UG&+R#aQnYRZSJ@EyfP#yQ58_?x0LPYp~82s?~ry#<$8D0d)X5u5=XBAY@#cva{biJ=Gssf;
|Ex|of8skGs$?(!~Zdau(e(0<6%fi3@yg)GSyO*NfYh%h^FoxQBxa?1V4dFMDPKjo8l;=04u+t<c?zSISW40EK_}Kc#4Q48-
`198SX_wBx3y&s!fo9T4Pp{980yao&L?V7HxU?9iVZen-yHksU;>2w#DSJRyy|Mhab+gt{0J|@;zDioPz{tg)iTE54}e7S8(Vp{Q
<8O*zeM-i05O529tj+ot_zeEaj=-
V{ffi4rED&kkCG1;X%gTOwx+|<hkQu95@Z}ZWtHq`G<P%(uNx_R%_}pQlnAx2|IQMZF+#P57?086^gdkMh#_D8oZV_0&DBqsKfn8
5SQ`s&uT^rKguTr#U8k$SfC^OXdxKaUdx)_>m2^Z$QiUGg^D2P3@ajJ{~bO!>#{N8fcOI-
G(gUcZ`U~;t@$EOKE(3$c(r4rK=|Z=$s4kph!l)$C*@%h2Im7DlKBgl?BWly4D*a_Z$}DU8KK-mX^~5(5ODfcn8F4h|9;i=_JRx_
ktF;`ZrzFTZ?p_@^*&3_4yqzrZ%;2AVC{5I%rnGR<8GHkiik9rb}X-|c9ti!gwU7jDk_JjOu{`I=E_(|b<+`By)jGM9jiV?%-
z7CoRY2sgKCD&y(!$wpv(=RJ7yH9@z1@2B0}N_(^z`nV($m#3IwO<$S9!*Y^rDI<#c`HZz*uEf5cFs0iWkuoj9A-
xxeub(5)6mR*6^HQHO1xJ7_dX#0Io07+TJUp4UDSRHd#KvnfKV-*JWk7N`=^Y%g@)32h13PI^p#-
PulRJcj((vJrAw8LA!zSXoML_Hu%pTJ_04>Z-YhZJ06Yz)-
{3wm~v}F9R!q(#QxTSkqua+(FCi5*;H;@tXMBp+cc3<50iKZ>kKX%^O!}Fh^hPj-
{a{Mc~d}nGmU=9jRxto%cgL_D&%XFn^J5W%JvNo$cT7&G1P?n<h-bychcv9*vpY!`@q)7*x19I0h~9CmW-yrMpZp$-
Z^AozYQ<&l<DN#ny&NGf$+KsIefGqbQBt1TXp~MMD}e?Ad9?+>H*koZ{fYtbdl<`NwpcZ8@z(j)X23T8YOw$zwsm+VG*emVPhla#
^i13nweUEKU8w_bb14+KTg%qaeeN*_yT`x6iVNY(%J4>}Qt*o$1)zkT7~15ZlzmwZO#8LrAEs^D-`2c-
dpmM$G9x6modp_0f9C7Jkwh9?lbVu)m!n?ZA2eV|Xa`{!AQU6X%n=oIq4A0r50()AvD8!1A^a3lI*roRq`ge^@mJaLtJVHc~&`3l
W?MB)v5>W}|q0FH|L_M~nNMg(2)n>deHp2!tiJ%$`2a_t%tU3bBBCtE(1tVK+If==X8DdvHbp<UjaKKm)NcCOyT%<zF2G6>o(MIK
A(ICQ5%#nZ|R0WGc9QQ*M3(>1P)I3FD1Zq0SQr6eXLd87SS^fOp|LSv`r2Tl&*kxX?eoz-
@$<=aH2kPWjvD5=zW@O=I*AW$`anVQqU=@hlPAjv!z(#qIjZj%3F(HzPKj_``<{V~i*}zHP`+)FgUm%#pM2Gy}RzY~Z)OIlBouH^
m8nLk_KMCOgL=H%64_;dH>x7v@4}lQsh$Kb@H_ySp9P15MqDy2r(G7efcGrEWGP@-
VTV7C?c9SaHXJ@0A`Lmt4EZ6TTQ$${|MCS0z~0D?)7k616fTOK8_Wrh<#)>?~C9{N7s);!8ES9M<3d^>@9WF&cH0C9?Y4(K}up_`
Jk{94g3q)~Os$ZmWMP=>e9TGsy#XQ#=ZA%J|^sS5=dl8vJ1x<L3*`xk)v;5byS^=kZBHD+M=Uows`t=tg1I#N^{tO9apKgK+NG1P
le-I|zG%C~j}aqu;7#c)L*$jkHCmp+ZR_ph8_ziy@jU@EJ|X5=CY6FnVowNG^-
1E|!)=1tv`Df@wzaED52X=eAf2e0k4=tW+sL!)}Hf&~hoMAUBt4B%%A|c->wIpDUzIqp3<{>XGH>rP>Ap)D7E?*2P(w-Czb@-
EIcWxi3(T;`fx2mupgqj%;b1d$n5dtAJ>X@W&w10&MUhfxvx$SRSVqjLnY^sb9GV3?O~j<aym-dU`wK?Dt4)*SY8|KFi!=MN3f^z
<I!+Io)-
#@Y`geRud7v)WT2p+>_hEn)9!`_pw!=qXF)2h+$8Zq;F@Sf|h7d9~v;P8SmwB{GLA;P1!JU%87L#t{@mTprWoLEnJ2fw!X+5|8$g
Vem|uS7YF{5j!T=-z|=jO?F{%hubzQ1LVx#nK{uL3{Na91{-
r22PvcctPhf9w<v72Xh(2Nnb_50Pkp*w@4Y?(s3KM4ArdMF(d<U(%bl-kTyBRbQ-
0{en^7Dc%AXvHJTs+SOU^+B`9F!_Z)FdL_tXC417;zrxP%K)&i%;0NSd~EbL(Dh?HWJ3=&9W^{qsT<XXDH^LF3WtlgH=>Z?1T@v&
m!0+Yq*mitJx9*s?!Vze`&6T?5z1tpvYBaHN3)U>&<;>CNikioX+<1vp8^^gA=hE^rap`r@twUf>9(D=Z)=XT;S=0shivGAI$2#7
a24ezOnX8kbLzu7jeZ!PyZIikAzUNz>_(Wv9s$KPFVn~+pw{Y0Jk(7E1mImmf#Bb_xSn?BxhHX96q?2o*3_xbOO=i+FWXijIi!~R
0xfwVl-I*8oy;dTiKc&qFNV4BW-t=uHgnEAWi2HNZOATK$LdwaUK6l)cXUB=v)8VFhcmcX{oo&-&L`OW`(6-9B-
3+vUTdP^Q6GlB}_v11^)TDgsRH_4?7(d#f&^~UPFByvcc{ZQx!-
4j%Y+EcdoARbpMVW<aYt25&s_Uh)zW~EPBB2pO1=@{pV}QlLhcvHqx(oUb>)0xv;~|*#u^!CGCkY2*(D6OE^pWk<}09E1wPEZ?wD
X^GgIJw<mN!9JoM>G}LGzCTAgii`>dS(TzZ9GGy|OLoMqaJ%jo==`bSRxkraOwlS5E0HONkc;<5lqSvM>^~8kL;%x5>n7<9S`7Ts
J{CYe9K<v?6M+J(ZFrd>Pgs^=1V3j&S3ShO<>O~!i+UtvRTw}BZe+ApXCGc2ji}W4uidovg6YEbgM#Scze8<b8<e)@zfg$`=$gJ-
&?8IyUU&5FoOx_eSjsz0_=)K&Ws9#5^&#I7<rFDmzSW5pN6mc7^orXhg1^tR%5XIUfyzvtbE*kUN%$Ng^!(uQs<Hy6=-
36=H(RT{>_<Md>?QPFZf{;@o$ekGuB9LM|Vp(PCm8*(As9Q2OY@rPsmsi7jUnj3!;K3ZmShvQdD%SkG-
y5pe{^`8MC?$Cp>~^n)Z!iO5C<-}4lh-
3+_m|tO3&dvvbNXLpk>Q1AxA|I4frm%JFooZhqxVe1xAEt<0GXuqu+c<!!tLk|b0jGIfXB9jQ#6>VaHr|^V)uEr^tI`@J1?%-
3a6o9baNp->*MWHm2vv&tzmVLno20{48J65^Z8=$-
n?W;!T*+q0#vYf=Xfmj>n1%IF)B%xDmr8k=4!jrG7@2MMy`_Eu!@qwcgz&bTO$>PazR5^?2!i6QyLI)=3WA#OKhGD<%%%m_w)?mM
x$%ch%F|1`RsF40^eFY?~tzkCiMdOh(z#%x$lX31kU&{!!@6CZX20*#pEBMcsck?IGI!4-
^i}>{qVw=l~UoC4q@?%BD*8$%{acofKz-l6Zoi1l-_88dJxk-
+Jzy0L8Ostc&?8@9$1GViz8E`#SGEl?sJesUW}ekm)|sOM%t<kbql8t>;udF#p$u{=U~$mBdA{*0K)R~MDwisTs9!axV)ep7G5Fk
`|t0iCw8(5JNDlLyg@D)WK1zJz=;uqk@F00rv806OO47;CSm!T+m%4f{JL1oYTK%7Cc&YdFYPV+T>$uXy~!G6jB#qkFgykFi|?12
swvkH?YF+WmZW6c0!?C9<+o<zC|F6!Pa@=RmGexpQWqExzjbR9ydY|>$}HAw(3w2fI)yX5HgSs8Zsfly898#VQoMy`y}ee!fzXyY
^lj76x!f=GTQ6;-!XyZ-bHvT*ezj154{kdkp@l|TBVNWR9(*BgI&|?nmRB}5<RxMvKpdUcpm-4-
(<RXFFcBE@`nAGXeTx9J<55vLfy8Fz!M^r8oYaRP7~6zeRW392u+LI{F8cBd)G&^f7QPd@tbc{DdYCY!-
Ts^V0`xIz9}HSU>Ww}&3at?W+inLJ8FSkaC(_knBpqgKsuo^L9F0ESePetNzo53CNvwUozX)4*aQk-
^GOjMG&9Te?8hrovp5bor9y?8I*=RNXLy{LoYpTi?VTveq9G5f#Y37n$2E$367$+Qk>Rem-G2W%>6Akj0P7pfW283{=B?-
OIs$M#l)Hc39;iZDr;x7dMb%2~H7mhVDvvwq<Y5fNn&yo|kPu+$Pu6*x$3(H&=dKl#}-
*+JK6hNtIN&otVMa?e3LeD>t$*Fo>{!s?~@%B)rJ&;QTbJJ<ZJ&O&YtXbU^XXy*fnKGc1TJ8KVPupz?s;0o^e7lD}4h#H;Z;);62
wTW4|LTV|Dqh!|eRKj>5toI3`q~&<$|S-
*7B}6%LK;I=nv!UP$aN!mJ(;O$wH3L!v8sva&Y4)uQr&!5*)e##vNIN?f&6i*LR_lJ*;f*eiSJhgA>CI5+C}_B`B4j%S^oSNn8+5
HkQpkM?~^306%cxCM`o$`$nepn9Bs<fzHD$oEMBjb)2c+ERd+u+pz#R*o`)#$eDBHzK#1?*M9Br?#3FB5G*gNJKi;&Et`PTrrR=a
U7QU?En$A5&l=4f`e(V!09@RVrQR=R;W$xn@Lr9#4q#kh1DX_|Yub}Z`@(iiJ(r*;~XfO8f31OaVNLCoM!J5MX;%&jg6X1r^g{s^
0qrf?fajOiuDEKaLe95vYyYNX}J&=idEGPiV`laI<<54~!sqq7A*}l3O%$|TDub-oj;3qk7UMsL9Z$elYk0j=<skjN1hp)x0G05m
yM(R^Nk2k<d>CI*qwj8ca%Q5n&bn11;a8X~_BTgW0&SjHTU(rlN{ePMWgVatd%wauDxDD-YLH_jbz(2VKEi$W>gqzh^I53de#MSl
SNUYbFI6!G==$W9z48@}RtiWYl0wFcYi95NyNt1AnVpc;(v66w)c-
WIhH)r;qs!rci`_sY~ygLXkEooQK;tDvUbaOtZ$hq6ci0%sDg8m`n@)nKZLLL+TEc~O$NmLT-T`@JgE|r1p-
&zfS_RUz{;;7LG(z7Zi@Cn?bBTN9f77<67F6uUfb(3)~(QbA00+Ah>(NyLM`?CUt4$wW#qF-g)YrH&+Qn~sr3hu-xQ{p_f-
jCaUnv9|&+=xa-GB}?uzXoj7C~v%#4}*PI?0a$|;P&^Y#~a6=$qvotp)bSE&cA1n{btw%r^v%^J3}F_cJGhuSvTlh^v>cJ31jk_(
pYuz5PNx${@=gwY0(mEInk*J_u8Mtdd-?1-*7DP#EEX-
vRM%m0q>{z;hlQ1nK7<lhK#9~aCoi^*Mrm<tk>I5btu7?F)G=25)l~A-&Du#Ht3ZR^g^7^*^TbtoDxchsCH)?D?FMlXoo|In-
xpot;R7dszSQ1?tv>**o0;(Zsp-YVfP;Eq=>WUYHo7Ej!~_Fvc@`_ioy5chgkis8Lyq1xH%6Afx?;T#r)+elp8X+6%mmU+kjD9HZ
dtEu7?)aEFv$V7v4hy_EA)L()hH^ur;ttkJ-xHQv>P3zA9}5W(r1ZEyv&7l1!L@Ac=NWpuY==ap=_z&#&A-
mE&o}`L6R~6mO&dw1aeHiL+#pe>N_h&|wv4m5HHFges{kBnfZC5d<{e7Ov%7ImX#fFrbmD<x3LBa(CTIZ<cp)OM|$X5m%49j!MBB
P7u_-I0WxGh$t=Q>_Ebkyo8xH*($zY|GD$~Wkqqp$t0qZUij@m9yLC9;!%r1St+J4W-
qNALE0l1)jUv%)dJfv#IS=}>p_M5Ft6b}K0-82glFlN19@dxMi8OwZas5+prTE}1~kUvjs~8=OrL-
j>fKIOm36;vI1!tnA`65R<i3_QQqb6S>O^(;1#2Zr727O)J8u<CCi)xYpAFn++UvA7`aQN^Sz-FEVV<m06vTGr+I_OLs-NZa$4lx
xPQ|mO?iQ&<e0`&yD%uuOigf&^*JnwtrX;_Nrg&YP{G|2BZ_D?bR3H9beTX$ZvqO)fuO_1)wc6@F|5=2`zu^RiXW|dCri8Ps^D$`
#^Uy%2|3Wl;{=xUif2z>2C5Kn6FRS?Kc%1-sE!G80wlSN=4nC{rs>+{Ft2}$_`*r-N6rjA2V*4a{=x-u4jYrp++V)u>q>*B-
v=zL<bxa;onJ+4BxOmEWdY$XYiy?Cdw1<ttFUYdayPM^Q?EK@ErxF=p3dCNR0ly}drt<6l_}m(qMw{<w6{{JfRV)9G+slttv6V?Z
$zd_fkYDm^wdLHSjzhfUiYmdZ^G6Ka6+eIKGjTS7iML$$-dzPN^UvTq)P2u6xn50|FIv;KsbZn88Ap~hz+`I%4c8SAI5^C-
{zzMvd<uA9*mXcFervXWFJM=?v%|#$zz{`d9eZA~TaI&skE|HCIP-tZ-Em?QYKV{5i#F%e)nKd5Q9}K4{l0XWCmRflW7QfYLf)<y
&@v@Y0eIvBM~ra5;0Cau0+>F%OCH(B8p1Sh)PQ#`+R)`YyozX`gEW0MmmxD_wggi!X$Xql<{<i?$idtZ?qN3$tlgq|c#Dn~zGTRr
m-gv*{E>lY-<im{1V<y<>sXkVP6QivInUn!>wWcsn~~%eh~B{)R;j_fFn0ZhdemTH!#TX_J!4Vu74-
rS1?q&?t=RVWe@1y~FqAq+nP69Zfv8WrB?>Pbms|V9crQx2fb6D=*b;-
Ep}@~Fo7`^cUXJ>Fs1RM7>F*KGHmd!|=y?uyn(yQt(x(*;=yeW)62r!6Q~M;XbQ)6c%t1n~1GUN6fye49BvxeG@!q^H6n(fJH;`U
4y9_t&g9SOfbFet@8?@n1cAr_Qzj<UBaRSU016iV|RmM%sn!cJsl&pvXPgVDTp$}9Vu~b7;68keq&(GJ6M30!+@0jl=bi3?|Bv_+
vd0ontWYTZqaX+Q4<%uWVVqPXblU@okp|2A48ArACYgM<RC8E+iV$2(Q&7=CM4;96p;Kj+_?!83@3_r$BD^(YGXK106wy};r`D;*
LhhH?$<w1gX#!wBR4d!GP5c)-FI|X>Zge)g>r{^8{pXC%FVnrp^^UJ>($dilOF~jV^YHN@yPn@yOT}0p*Gil*bGO-
U#L72pUj#)3I&Ex2?(MZhef0LKT-r>Hi?Z%L{p{zU~=kfbF-q|!&$3KNS*t~?SCpEC`3BOxfR<8)*P-
6+$ikg^_ei~CbNFUUkTF(PI4I+Rm(^lN1gd+zvshF_h$iy0K3#IUY(X*0MBMbuTk!J4zIl5fp&-
(I|)A@YE{sfH$3Q7rpIThF<$S?rT+ZiE!%Vc;*H^3z;k=wd8f83ZbIi)s2h&90Q*3b(s%0Jte!8tX@q}c|#aAK<W-
?2~Cdhq#Sf2j*>6)!>E0xb#i+wI?Rkv))rb78AGavhX_Cs%BgTOY|hn?#NIr#)grb9$(@Vl=9Lk<7V(p9r3Q<&eccz_Gu@RVAV<p
~BbzfF&7}@S6zRY4|!H;;Opp-CBGU7p2+EC2V`T&XWr=9K~ly_I2EPSdBsiXGH7M;w^B9V>H40U02F-
LV*w3zBS5yTw0^BV&YzCU|UTE;s|tSMBYa7^IbzN5??zlljjs_0{7y?;i~AGWcxW%7gj{zH>pK~lBF_Ybid+tbg!gq;m9QIZK@?2
CPkUYQFIls>T8=Z6wcIy`KeDD0W!6U)hEKw<09P6_aC25GkkGH9W|`k6kc>7{xOQThx&l~N+rk&5})ng{2Wmo;IYW1GM~qrymQ<a
T{&vvn23J0I#C-|2NRC9(VlYvu~%o{iUWY|b#a{VnF1F5#I?#RV8vy(s1UMwF{)y!$Ai%brMKOeCn>4w!?G-g<dB`i?PBYNb5;)-
{3rqG;X6J4Y02{N);tua#G?+ym-^B8Ld)M<C}c07dQ&YT`l}RXNVCxKa@GJmkadiCCSk^a%AeIFt*V7~lx^$z#3_&(-
#{hvMbCdIZNHZ{Ig$k-
R}{9cDy(~nraYK1%h*~nMM=ApZZFAP_5t}aGnAeE$v{P=Ca(>%D==!%Fq3PxyfE}X*!#*nE(StO=1t;ef5TJb;p_O0(>Whb%>nM5
^n>8x2~-#w6VM#!rrR~jD4#)lsrvSe0m#S~?YC;b;KOY7x_YkRE+HP5{)i?;@r!c?=UR}V^6-
h*S`@Y5V?GzQ##di1#^OI$;CS7iq&sgAs(_aa=e$}6#xw1{`ZLV(NQ){ZF**na<qG;zd-VZU+tVR7z`3$y!cuNku&XHN`Q&Z(sMs
&KgOZlQ9C+?JkiUmGEEy)i<@~2k&>B{{ehKa9uCPt6a=9C2tIsGnKC<7=iSdcI%q%yhIQ-
~B)T%aJOoWx>%71AMX+xLV<qwL4`q}a@V#A+Ng7a~r8Uje7hERT{4sg3(!v8p{r7JEQriFI@aP`sgU&47~s^tX?;9-
`Gs{IDi;|HSk+Ep4d0x~<3LxG_yvm9!J`?cQ3%D>F;MTFRJzEfP5;jpKTcfn$BFaM?*%Wx--9ZuHly0AH<t~xYn95I)*3k8=bzlO
^QSG-&w@{-+oe!gP1g*=vPgQP&4Loh(jE<CDPKrOes6fluhu@Ksy*qG(GWEKK7a8g2l+-
@9&f%^_9V!tLBqnaQ1p>@kp&E&dvKIY+{2GJ%qo!FSB5ybv*H&nE`Ig<gcHB=bBS$~85c2^HG(v@mub2^l;uT_aE2tt2raN)C7q3
_H2all*T?ptT$cUT4dXCN0z^OLQ`hV(l+HtWAwb!(9#u1^rJ7P?}MpFANJ^}O#Nd})-
U0L)r9%eJ@{(pUANMbtXQ1}=0JdF0_tx&2Smr+h=tIW(o?ia(<bzp8q@elRDSJl=AjaGGi?er0!?ObFgZx6(OE4x#>t&e`AX$$8x
V*XU=*;k`?OXV=yRwPIIqWyB!uPXGdT(wO^8htq9aLz`Gj7PvPof=E(z!HJ9EtLho&8)<vMr}3=uXy3Uz1JFQq|Io0y%9A+)`FZ%
iHez2mhAm3|4GgK(aB+wi+?5+gf;G#CI0iJ(`9<33kFa0-=tBmHeL@49rcWorcqir!G7K|v$Bl8x-Q-
O6q~GrI680^MO<jXdkjU}vTIk`khp0!1!-I_9Lfds!f0=+o=E32FIDm}Mv0S5h*D#Y-3S_62dV-
stp(hHm3Y4RON@d)*TL~JbL=&relv!!sP|=a#uh3{aj80qgIZ{uT&HH}7GcP=kt^eRIw#*#MbFxD{nmeES`&jlR!>E+Q)8m4cm-Q
oibXn{;*3DQ4fFE$cnxo#JWt_l+_`8APSsQd{N6Shkj3YzazpW3N<&Z$#2Q6x|<7Uc5BsJ-
R+UiCCV&&@=kT~160*!0<HzbJOI@^lN&6yZn@qax|&YtseOhQAO+yehqmk&?1G_bNT!8`qHfgt!kH_v>JoHHamC_O=R@|c6d&^pe
{1s)(gL=Gj?HFc_>kBEh-_D~?k*Xl-Xkzg-V7ND*XEOAOmRp&rJoOKOXCYA)v@!_IJS@-
!2hg{rB{e9@@o{yFC$k_S#90w4QgPlQ03vr)wQ(c~iw(8K5PxYi;l_r3HA+MgX%>#40K=R<jU0nJ?-
a%TjMRc7I*lwJAI5{TQga|vpudB>+!0>wekoI=U#aQ3QX^|WM&X~ZxTAz%GU}!oJ^4Qe!{Ord##0}5V7^s!{yDK7{C(Zqqge_sW@
U@^uTc6OQ!L5~v)4<==4UITb-xAo}ElSwxqkN#r$0ul-
(yz<zyj6MS6l79imwHvmfz#VGpJ^lzrRvbpeF6XlewaMc%KN4|xqX{0Tv5B`GpH6I(F$3?`4k&OrRi2xZv@MM<pU2P)cy>~U+43D
)_0unIT{SuQHMh&zS1{Pifo3PSJ7jATb!#&gBNOl<<3tQToB8$<zJ^UHNwhmD{ikoGK8?Kt|bgC%b613ywVj9zP9|{5L?!Gx(A<Z
(a?Z7Mf@NFOJeB*&Sa#lYV81cqgR?_T|>Ji%v!`id+8=~MVy_4nFo0CDh$_piXe#V6T;LA<Q_csN>b&BcW=^|yEaC!EV&<FhPVH$
OMp<U0&D1ZrwO84$e3!%c2Cu-hzot?G=SbG;T~L<RlmqDW4HH6-
c>iT>924{Trbf~7rZG~SN(=V_h@G}Qc_j4+m38uJaEw2Mi1hc%MN4JY8hTwZg+s1bDuaQ^RGPAuh$u_44ykhS(RJzEdeTT&tAQAQ
fzIf`9SN&MnY;OPF>&%GfVduW!o~pntQ@$3rDNU%o`;#5Jj>afjLS>IzCy&5APg0IW|j<olV8!FDnF(xff8X@zv|+FS#!ZCfhlsQ
A}E;b&&#sN-=9|mO6oWIE9?5=yjAHMCvi!<VKMJ%6f3E&8*&!&s;$nq8A@~iF*jgqKt<lBV}9T<|Usa+&5v6+syVN`hJ@j$}-
Cz7YQpY?6?YP+5M0y@67u<B0D$>mYLH_IXs~!7N+1Ay+cq>RJx?{l`x2PAcu6s9IQhkrwRF|<jW-
e6#wnDv~eD;8lycZ(~)EFOx|Z^+)vg;M1ostXJ;nRg=FwVjd~QX?)jFtMw_wo7rMcBFegM+LSixsBDrs8Iq^?Z8;c$>39j<jLLT-
7`s3zVeFaV-s<t<?s?z<%${Y<##?mnJh4X~5H&{=?^N+Lquz*5{0I*KSWSoO6vG73pDQ_^2)q^sKh_Q}*Ea|p7TX^-
Jf1jEVi@0iwp0McCM(|%f%A4o#gu@DQ1hAySV5Xfm65(sL_@_1eff9Im)geFw%63n1)3Eo&26w+mS`*!J;LWm`!A$WEpc_LFUup2
iv&*igZ>s4HyG-=6Hq}RC5}QJ?{k-T<kX7K{kMeg%#+JWGw0;i2Z1EjaV}d?LBnneii3FnLliPn-*c33L*wp-YJ68!#<zx;ZDfig
pnfMko+Z!s=1)kNZxD}Av+F=0Sfvo$vb(1Mt&fpbIwUh@~a%n)oKhRzY!n0Eh7$|t}^<-
w~CU*6S%M$~YB0#ku8@N3KX3TBbbtvFWEum=UxakVkKAV#ysK}KbZ-GA04KDM(SJV9g$mm{1N1x~vE7SY6^tLaq;QlRq#;+c}-
9S^{i?51+3B)u`1%-Gfhpa|fh7)Ub!V%zvhY`??eO^6;bd=+7FVEClV~ETtQ+R*n36Uuu;rck#dNrZ&g4-ZsS)j-
hF(S>yqRaKodV;qyuAQaK{Arq8l}fIIlve2jbA2D^Wv*7It|xH2ok@{h1ur#v)-_6@S-
^y|4h+J4ox9>4?@$3RA1^lu0TYft$P^PRah&7Tcdr8OI)O#L5}Ds<iuJkxz4gVanGWPNSg*Pp7MPQE|D!CrKeVwtyd)WVG1u9pOk
8@bvw_p}dGtPcxd>D3zL;7YR-
{;M?i92UG2GtE4UhO1O0uxZc!CdGU#Ek>`~3o~K{FuxTk+dswn<s@9dN}_25$X}pwi(u3iM0~Qb($|wh%x&xGylltNFucUI$1i{n
9=O_nlyk{k#tBh}6A8LWb1{h6b#Y(<52IEh^Z<SE@6#PbtueDAtQyJ;*zd$0r<#?yq(_Io}vVJF|*3Hic2t0t_sJ`q7|lNA6h?!0
t0rL}KL<;t!jZJ49B`gpRza(~=LUOdEp!UHiTnq3s{0mLZm5CIKkp{hGNvXY>S~rxS8lxh907Q%*~3_GLQtd%Fh)+b4Rum=pge#o
Y=1&9=R@LuG>*KfP<)r7<)Ml!2PzH)m_XllKseIf>#RU<^B>l2qY}BI2_TpocGC%Y{W$O3?1r@-
y&otZ+VwLH08WvoAw1y~>G(s2UZgv>>XutgQ9;_Bh@Yixv)x)YeUk*ohP3iK}o@kR5D)+GowZJgOBN6&1T%KI<n_R4Gnbw8h-
=Pj@ue^+tQEJYogh+a<248eT5w<cP&o8M=GGU86Y^3_#0=jq*odg!+hQ+OgGcq~@JYtp3o{kt3x_w`#`c?xnXn{XZ}Q3`(8|K2O`
l@J*@m5t%&JOSJ~gIpzAU&&fLnlur9{o4!j`p_+Q^07MIkwk;waGbL=3SQ?CuAO-
!MRsp29vg2yDjQf=@7Djq?GMh)GVG|i01JgJs2P^m&C>uSN82!ra`xfT!fz2!YJ8o^lF-?`7%-6=P@-
@Xglw+hbxAOk12f2I5ne?!;?>!Nx1EeXeIk>b(3{6#sJVT|)Rb|ANAr_rSq|{pB@*lg2dT_q|j_iAtF1<y>|BnTE;Q>Nm{H?}Kw1
FXA=FSRH?aLo%ISKw{rt04F+&j0-)wUlQyjw(a-
>&xYL|Yj9Ap`Ga;t5$i+)t_zPzG&BC~miBzw667vE7AocBzH9B7#V?!Gn?pq`ox#c`zGTf7_efQVp+%^E^N@m3zDRm2Q!c(RL}Ev
o&do`&gc>IRa>wp#{0T>u~Ee3h$cd3w`Sg7-
@8&1lJC9Ki!No)3Y3x%4YVZO3GWosNE8guzq=>N3#8_w4JLm29<Qnd|1lv@xee%0~0mb6Y1FUqLjc7YCue_MggHgO{ZRyZV7}&zk
eKQGy8Gu=?n33R%;}bE4kBbpqH)E<d-
MWIFrtDt91d9_%DP+iD<*|>f+nFKSGQt#(eJ*<ri|{bx01>6CCpZg!+W`$d+%o5i^apPzd4$o}c<7RRFB8fus>gT$C|ks8yo6Xo{
n^&Q}ytI-Gmg_%JYFLdbD#PiBg^qszaZ3H6J*<f&8(0qNO}MFA*|8kfWtB207ykK)M;4Ay!~yc+R;W|7cg(d8pGUjo9E%F`q94#7
x!>~0=J`FB2Qi2_JuD@IP3QxJzNDkEFc3aJVaM~YZuVMniVez4sW)KvbVaJV!Qt|?7;YhaL>5Oo;=aBWn-R`-
BX<v9Y#wyColZGH=VydX<vwIS?xH{&>Z3Tf6%ly<p?DIBq9)<v+^-Sc>-
Io#hUFRU#l%#_DPf7>Qz&C`C|0Sb(b@gGx;$p0R_g+<&YPtAn?w8{XTjb*M=J1D+>$gF8W3i=b`s2`uOaPdYbr_FhBx<d(w#F#&O
C6@o>WurG&>+nP+923)?+l>YIG&>N4Coi{Gusqg$YWTCyE-$jiFcG76eNw9?YJqnVY7al=z~HvKIJJm88-
p_Xq9MY7p^GArK70yul_g>)@VirJBL0NQ1>5aybEpg$cP_k#91#!Or@n=-fZ-
q1=Eqo1sqlvNx&5L<izRdk{CM~;$Mw*`<+WDpG)Uh0+ig5Bx*{sgtrCi#kd6I$Izo<^hP72ic#Rzo<-
66SQJU;^Y}14z#p~}8%UmqhmnQ_0#+M3wvpxl&gOa8v`D^Sr5`&qW+5po*zB>QnWi|ou&UI1|H7s|^iA-
i4&`VNQYEp0>1om&goYY2~-=b^N?`qZfZ?M~y*MJy;ZwXbC7+ki3{1||Ge5fkQWdw!-
|LrFi<rrJ7^Z^$#B`pX#Boa{$MAPa?i6ouozy?BEa<x_by1SrXIqX%TDN2>#q9!8cY5o2f)~-
D>z({L$2UcRIe>`K|j_*PC5}c89*m{Ea+3M-*5XBtD2ir>Kkg}k4qcwo|K2w(Z3!+|rHdPZIAgDai@Ut+h*Har^T3C<dF05r-
G~lfEwP8|vsBmx8v4vT6+kM4F?O~3X#VP)W2a-
?ALwbiU{#~jaqPQb}$Hs=O0P}(mvoS{Ss}2{~RPaqRCQvBQaS#6n_im#WD%wK#g|9af?29(Zaw@DGrsmFaO!u`pf3<3;hFUY#6mf
~4_z(#Ne|wDiRjv!`8<oUZBHF}136WwIkCm)>s%+7Lh*~PEeG{KFK1^l6dUgAqDCkS;X&qJSvH9kCsHGywfIW)H*tR`zTPVYklW`
xS)^VT5We3isaaz60wsDB&^5i4;di3C#a)d&vD{OZV3cI0(x;6K6(<cL*I`7B1uae+j<Wdi=UuPP~DKPt*P7y+`ap^b0f_qEjMBT
#1u~jM*jcnR6_YT>?AJg-XbA<(jmLe>*^5kK-
{v^6MYRc$h7}56QTZKy3A(Lh(Lk{+dy97CL5yhyqYVu1;lBamv1@)G<+_}^;luZ2!^3gRfp7}@u;5G}l{o?tlY5u#D5nwO`&uv?o
euE_-
s;qdz2&Fm>t_*O*h*e#ZVbZAL>T8V!zpXZ9gDPO^V2dbt^^bcQr&4wf6DIPO10vdmYL=!OjwCA6G1>>qu4Up!9uCvQV8%?pYPnB?
odslR&0Ob3i&rAuH_r?C$gjp2+9u55aTXKhprBgwGQW(@lV)RDA_dOFf_H1^XYQne<!BxGyV{(2Km}6j{0rZf;_Y;T{h7MHA8w_8
Rt|_!nGVq~GN7vM82ATA^ctu?W*EI7y29rwMU&jT62uz?aaDp)WdcD+#lLa~Yv?|gtN;3<Mo(BF(u?lO*FOv4VHNQ1h&?Ju`@6Tx
^I^v<w?J{_H`MN`BwWeSs@`()qK)(oK!=$wrR!7mtGFK%{gJbMr1>}A(txdE*cIfpQ9VoRa8_bYCPc9H&`UzQLwg=~$6qlAwB2hg
3Uu3(_{+^}O@3DRjt#9>8sd)0r_3Ii1)c)dgMv2vXJ9pC4H~AfQB-
6RLbzbZ$#w#Jd2pcptU0O7Bgh$jmkwdOI<pJW;}Y7kaJ3!#wrBi5dkRYDv~DksUcE;Do!qZdJD!BK&lg5YC88+9Dw)aFzAlk=S-
zY1!|3q70{1Tt6mm`9Io%oMA$fe3<JAr8U5L~3m{aoa(Er2AGByNtBw`KHR#^*`60gi7=HDdiLA<kn*b<32xDObuU1kTHBBStui{
sYCD?yBp4|<JFe!Uy?iG#AdFx174F+zJlo#XCkTZtr&@lMtC_P(18ZSn`7+XTXdylYOt<60+KcpIZ=&9nJz*Ya*3t^?3&&pQWxuJ
hx0^ii<>%_<;XrjvA)hgukUvLe8}l$N3>Ip7WM?{%t7arbZ<A0*kyP+0t>Gz$A(OX9as1%{aXnWdy?f2<9sH2aK+PXnV=m~bgE4&
Qpy4Yo>NyjC4J5hWT5$rX+nNe9(9w7vxs3&QP3-
;FzR(G&i3QTeZH?BG6HXZzt7JRxxw0ZC0YrxPM#Z0ryM9+RaIqm=E5!bb%=OQ#0}gu4>oz+f!U15kUghNW&$`r{SYO~;OgX$U0yR
h4_4)-X7Rv8CzIGe=Phsv$dM<FKwc|27djrYd^opCW1ceK#hlh%^K7EhtdI77L{xPU}5j-
Dg(GZcR|<s=~!t#TFqncI>H`%2;JqQsG&D&t`2FXm5^q{IxZ`y`w_X41+{2nI#q}oA%Rw+=`8u4X&pR|C-
YDAr&G>CnHjn^v9F~6^dhX<Y-uW)1#Lg`>=@>a2yYTWoTJXkOSptJeG(`e%P6r8(V~j5OOYW%X<}Dmr$dsatyzSsHjOc)~?V;rs-
Gn2YE!`b9l}UK1sxqI}t@0Gn5YDNZ5ZiK@iyx;k)JKK=+D8{Y3J&8`epCCMdYS$&1wmO4}EVcPKhT2=thA8qnxeC(Rx|q(GD-
p~QqL->-2*YqpJ2RKQ6CV7BloPVq{uA>l34)EzxI`4DDh5NK+PLbG2te-fqej0h#w$=8KATryhtb5<ag97>D2{&Xqpfu<Wb4QHMz
^5M0p6^pb`TgWkb%U7K@K-Cb~u$Wdq#l|x#o<&=jwT_jbEu6{GuryA^hSE<46yL-
C<%MXOthW}qTDPS6tWOC|NvI3N?UEL}iAW&4Sxy%9=M<m|1+PE5^uS?^l^ArbFAFbMH9QB*(v=jaDzwTzva*jM>8oW&?@cKdHoti
UhSB&J;djnkKn?kpp@6ROxf~nCdp|Ea27+tggnzF(yBx!wdTsBxHzhP6ekw;>*S%VtF{56ZB1tH0q{_N_B!=m;Nw-ap?0*F$50GY
r`z|fIDH6sV@l{YgiUYf+dyosJNL|M;=Pou24+ayJ43|86F-RsrBQ|8A>>lT0j*2eHBuAMG+pA#}F8}}l9t-
`h1kmu`00HE7fRGmedlK6%vBYQl0ssI200dcD
"""


class OriginalNativeFixtureControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import base64
        import io
        import lzma
        import tarfile
        cls.directory = tempfile.TemporaryDirectory(prefix='w1-compact-original-fixture-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        compressed = base64.b85decode(''.join(REAL_FIXTURE_ARCHIVE_B85.split()))
        if hashlib.sha256(compressed).hexdigest() != REAL_FIXTURE_ARCHIVE_SHA256:
            raise ValueError('FIXTURE_ARCHIVE_SHA256')
        raw = lzma.decompress(compressed)
        if len(raw) > 512 * 1024:
            raise ValueError('FIXTURE_ARCHIVE_LIMIT')
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
            names = archive.getnames()
            expected_names = {'origin.json','setupzero.stdout','minerzero.stdout','cap8.stdout','minertight.stdout'}
            if set(names) != expected_names or len(names) != len(expected_names):
                raise ValueError('FIXTURE_MEMBERS')
            for member in archive.getmembers():
                if not member.isfile() or member.size > 256 * 1024:
                    raise ValueError('FIXTURE_MEMBER')
                data = archive.extractfile(member).read()
                (cls.root/member.name).write_bytes(data)
        cls.origin = json.loads((cls.root/'origin.json').read_bytes())
        if cls.origin['binary_sha256'] != '5a9e9154007a549ac482b24adcdf730ecd5d8d2b213eba252026c4a0205ceeb0':
            raise ValueError('ORIGINAL_NATIVE_BINARY_PIN')
        if cls.origin['source_sha256'] != {
            'trillionnium/crates/trnm-pon-node/examples/pon_w1_compact_miner_research.rs':'5349bcd5b1c43d6383db286054184cc47f6bb7671faa8837a97130d1f2cc153d',
            'trillionnium/crates/trnm-pon-node/examples/support/w1_compact_miner.rs':'77b8af8c2204f7688fcd3c7f47f20efdf4a98409cf503841f2c297964d200d9a',
            'trillionnium/crates/trnm-pon-node/examples/support/w1_deferred_producer.rs':'734a6bc1d86a34c727683032e7cdac115ccc20d57daee53f4debfde35bcf72e1'}:
            raise ValueError('ORIGINAL_NATIVE_SOURCE_PINS')
        budgets={'setupzero':(0,1000000000),'minerzero':(1000000000,0),
                 'cap8':(1000000000,1000000000),'minertight':(1000000000,100000)}
        cls.results = {}
        for job in cls.origin['jobs']:
            setup,miner=budgets[job['name']]
            args=['--setup-budget-ns',str(setup),'--miner-budget-ns',str(miner),'--max-attempts','8','--seed','7199']
            if job['args'] != args or job['complete'] is not True:
                raise ValueError('ORIGINAL_NATIVE_ARGUMENT_PIN')
            path=cls.root/(job['name']+'.stdout'); data=path.read_bytes()
            if len(data) != job['stdout_bytes'] or hashlib.sha256(data).hexdigest() != job['stdout_sha256']:
                raise ValueError('ORIGINAL_NATIVE_RAW_PIN')
            cls.results[job['name']]=c.read_compact(path, expected_options=c.options_from_args(args))

    def original_rows(self, name):
        return [(tag,payload if tag in (c.SETUP_PACKET,c.WINNER) else c.decode_json(payload,tag))
                for tag,payload in c.FrameStream(self.root/(name+'.stdout'))]

    def reject(self, name, mutate, label):
        rows=self.original_rows(name)
        mutate(rows)
        path=self.root/'mutated-copy.bin'
        path.write_bytes(encode_rows(rows))
        with self.assertRaisesRegex(ValueError,label):
            c.read_compact(path)

    def test_all_actual_functional_bytes_have_full_scalar_replay(self):
        self.assertEqual(len(self.results),4)
        self.assertEqual(sum(r['full_proof_records_replayed'] for r in self.results.values()),7)
        self.assertEqual(sum(r['deterministic_attempts_recomputed'] for r in self.results.values()),12)
        cap=self.results['cap8']
        self.assertEqual((cap['attempts'],cap['target_hits'],cap['target_misses']),(8,3,5))
        self.assertEqual(cap['full_winners_available_by_B'],3)
        self.assertTrue(cap['censored_by_attempt_cap'])
        self.assertEqual(cap['original_miss_records'],0)
        self.assertEqual(len(cap['opportunity_identities']),8)
        self.assertEqual(len(set(cap['opportunity_identities'])),8)

    def test_actual_late_winner_is_retained_but_not_credited(self):
        row=self.results['minertight']
        self.assertEqual((row['attempts'],row['native_accepted'],row['native_accepted_from_B']),(1,1,0))
        self.assertEqual((row['late_attempts'],row['late_winners']),(1,1))
        self.assertEqual(row['full_winners_available_by_B'],0)

    def test_actual_zero_budgets_do_no_research(self):
        self.assertFalse(self.results['setupzero']['setup_complete'])
        self.assertTrue(self.results['minerzero']['setup_complete'])
        for name in ('setupzero','minerzero'):
            self.assertEqual(self.results[name]['attempts'],0)
            self.assertEqual(self.results[name]['native_accepted_from_B'],0)

    def test_winning_product_change_is_not_accepted_by_ticket_only(self):
        def mutate(rows):
            index=next(i for i,(tag,_) in enumerate(rows) if tag==c.WINNER)
            tag,payload=rows[index]; payload=bytearray(payload)
            offset=8+c.HEADER_BYTES+2+4+2*4096*4
            value,=struct.unpack_from('<I',payload,offset)
            struct.pack_into('<I',payload,offset,(value+1)%4294967291)
            rows[index]=(tag,bytes(payload))
        self.reject('cap8',mutate,'ORIGINAL_WINNER_PACKET_SCALAR_REPLAY')

    def test_false_miss_commitment_cannot_be_reconciled_by_matching_summary(self):
        def mutate(rows):
            seal=next(v for tag,v in rows if tag==c.SEAL)
            audit=next(v for tag,v in rows if tag==c.AUDIT)
            old=seal['trace_commitment']
            changed=('0' if old[0]!='0' else '1')+old[1:]
            seal['trace_commitment']=audit['trace_commitment']=changed
        self.reject('cap8',mutate,'ALL_MISS_TRACE_COMMITMENT_SCALAR_REPLAY')

    def test_hidden_winner_cannot_be_relabelled_as_an_unprinted_miss(self):
        def mutate(rows):
            first=next(i for i,(tag,_) in enumerate(rows) if tag==c.WINNER)
            ordinal,=struct.unpack_from('<Q',rows[first][1]); del rows[first]
            receiver=next(i for i,(tag,v) in enumerate(rows) if tag==c.RECEIVER and v['ordinal']==ordinal)
            del rows[receiver]
            seal=next(v for tag,v in rows if tag==c.SEAL)
            seal['target_hits']-=1; seal['target_misses']+=1
            seal['full_winners_available_by_b']-=1; seal['winner_packet_bytes']-=c.PACKET_BYTES
            audit=next(v for tag,v in rows if tag==c.AUDIT)
            audit['research_hits']-=1; audit['research_misses']+=1
            end=next(v for tag,v in rows if tag==c.END)
            end['target_hits']-=1; end['target_misses']+=1
            end['full_winners_available_by_B']-=1; end['native_accepted']-=1; end['native_accepted_from_B']-=1
        self.reject('cap8',mutate,'COMPLETE_WINNER_SET_SCALAR_REPLAY')

    def test_actual_late_proof_cannot_gain_credit_by_counter_edits(self):
        def mutate(rows):
            seal=next(v for tag,v in rows if tag==c.SEAL)
            seal['attempts_available_by_b']=1; seal['full_winners_available_by_b']=1
        self.reject('minertight',mutate,'BY_B_PREFIX')

    def test_duplicate_winner_identity_rejected(self):
        def mutate(rows):
            first=next(i for i,(tag,_) in enumerate(rows) if tag==c.WINNER)
            rows.insert(first+1,rows[first])
        self.reject('cap8',mutate,'WINNER_ORDINAL')

    def test_native_receipt_cannot_change_original_block_identity(self):
        def mutate(rows):
            next(v for tag,v in rows if tag==c.RECEIVER)['native_block_id']='00'*32
        self.reject('cap8',mutate,'NATIVE_RECEIPT_BINDING')

    def test_receiver_cannot_run_before_the_seal(self):
        def mutate(rows):
            receiver=next(i for i,(tag,_) in enumerate(rows) if tag==c.RECEIVER)
            moved=rows.pop(receiver)
            seal=next(i for i,(tag,_) in enumerate(rows) if tag==c.SEAL)
            rows.insert(seal,moved)
        self.reject('cap8',mutate,'RECEIVER_ORDER')

    def test_extra_byte_is_not_a_production_packet(self):
        def mutate(rows):
            index=next(i for i,(tag,_) in enumerate(rows) if tag==c.WINNER)
            tag,payload=rows[index]; rows[index]=(tag,payload+b'\0')
        self.reject('cap8',mutate,'WINNER_FRAME_LENGTH')

    def test_real_original_budget_does_not_accept_bool_stamp_alias(self):
        def mutate(rows):
            next(v for tag,v in rows if tag==c.SEAL)['stop_poll']['process_cpu_ns']=False
        self.reject('cap8',mutate,'CPU_STAMP')


if __name__ == '__main__':
    unittest.main()
