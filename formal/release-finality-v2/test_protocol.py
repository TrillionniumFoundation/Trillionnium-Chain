"""Controlled fixture keys only; no independent-operator or production claim."""
import copy
import hashlib
import itertools
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from protocol import *
from verify_certificate import verify as separate_verify

ZERO = "0"*64
EVAL = hashlib.sha256(b"frozen-local-test-evaluation-not-quality-proof").hexdigest()

def ordered(votes):
    return sorted(votes, key=lambda x: x["signer"])

def local_application(statement, artifact):
    require(statement["evaluation"] == EVAL, "APPLICATION_EVALUATION_PIN")

def keys_for(n, offset=0):
    return sorted([Ed25519PrivateKey.from_private_bytes(hashlib.sha256(
        f"PUBLIC TEST FIXTURE ONLY {offset+i}".encode()).digest()) for i in range(n)], key=key_id)

def members_for(keys, epoch=0, f=1, q=None):
    n = len(keys)
    return dict(schema="trnm-release-committee-v2", genesis="a"*64, epoch=epoch,
                members=[key_id(k) for k in keys], fault_bound=f, quorum=(n+f)//2+1 if q is None else q)

class Fixture:
    def __init__(self, n=4, epoch=0, ctx=None, offset=0):
        self.tmp = tempfile.TemporaryDirectory()
        self.keys = keys_for(n, offset)
        self.m = members_for(self.keys, epoch)
        self.ctx = ctx or context(self.m, 1, ZERO, hashlib.sha256(b"parent").hexdigest())
        self.nodes = [Replica(Path(self.tmp.name)/str(i), self.m, self.ctx, key, local_application) for i, key in enumerate(self.keys)]

    def close(self):
        for node in self.nodes:
            node.close()
        self.tmp.cleanup()

    def statement(self, artifact=b"candidate A", next_committee=None):
        return dict(context=identity(self.ctx), model=hashlib.sha256(artifact).hexdigest(), evaluation=EVAL,
                    availability=hashlib.sha256(b"manifest"+artifact).hexdigest(), retention_height=self.ctx["height"]+100,
                    state_root=hashlib.sha256(b"state"+artifact).hexdigest(), next_committee=next_committee)

    def da(self, statement, artifact=b"candidate A"):
        return certificate(self.ctx, 0, "availability", identity(statement), ordered(
            [r.attest(statement, artifact) for r in self.nodes]), self.m)

    def propose(self, view, statement, artifact=b"candidate A", ids=None):
        ids = list(range(len(self.nodes))) if ids is None else ids
        reports = ordered([self.nodes[i].new_view(view) for i in ids])
        da = self.da(statement, artifact)
        p = proposal(self.keys[(view-1) % len(self.keys)], self.ctx, self.m, view, reports, statement, da)
        return p, da

    def run(self, view=1, artifact=b"candidate A", next_committee=None, decide=True, ids=None):
        ids = list(range(len(self.nodes))) if ids is None else ids
        s = self.statement(artifact, next_committee)
        p, da = self.propose(view, s, artifact, ids)
        votes = ordered([self.nodes[i].prepare(p, artifact) for i in ids])
        pq = certificate(self.ctx, view, "prepare", identity(s), votes, self.m)
        pc = ordered([self.nodes[i].receive_qc(pq, s, artifact, da) for i in ids])
        pcq = certificate(self.ctx, view, "precommit", identity(s), pc, self.m)
        cv = ordered([self.nodes[i].receive_qc(pcq, s, artifact, da, pq) for i in ids])
        cq = certificate(self.ctx, view, "commit", identity(s), cv, self.m)
        bundle = dict(context=self.ctx, statement=s, availability=da, commit=cq)
        if decide:
            for r in self.nodes:
                r.receive_qc(cq, s, artifact, da)
        return bundle, pq, pcq

class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
    def tearDown(self):
        self.f.close()

    def test_quorum_original_counterexample(self):
        with self.assertRaises(Refusal):
            quorum(5, 1, 3)
        self.assertEqual(quorum(5, 1, 4), 4)
        self.assertEqual(quorum(4, 1, 3), 3)

    def test_exhaustive_admitted_quorum_intersections(self):
        for n in range(1, 10):
            for f in range((n-1)//3+1):
                for q in range(1, n+1):
                    try:
                        quorum(n, f, q)
                    except Refusal:
                        continue
                    sets = [set(x) for x in itertools.combinations(range(n), q)]
                    self.assertTrue(all(len(a & b) > f for a in sets for b in sets), (n,f,q))
                    self.assertLessEqual(q, n-f)

    def test_reject_unavailable_quorum(self):
        with self.assertRaises(Refusal):
            quorum(4, 1, 4)

    def test_reject_bool_and_large_manifest(self):
        for triple in ((True,0,1), (4,True,3), (4,1,True), (33,0,33)):
            with self.assertRaises(Refusal):
                quorum(*triple)

    def test_duplicate_identity_and_manifest_shape(self):
        m = copy.deepcopy(self.f.m); m["members"][1] = m["members"][0]
        with self.assertRaises(Refusal):
            manifest(m)
        m = copy.deepcopy(self.f.m); m["untrusted_weight"] = 1
        with self.assertRaises(Refusal):
            manifest(m)

    def test_full_three_phase_decision_and_separate_reader(self):
        b, _, _ = self.f.run()
        a = verify_decision(b, self.f.ctx, self.f.m)
        z = separate_verify(canonical(b), canonical(self.f.m), canonical(self.f.ctx))
        self.assertEqual(a, z)
        self.assertFalse(a["hepta_final_use"])
        for r in self.f.nodes:
            self.assertEqual(r.decision(), b)

    def test_five_member_live_with_one_absent(self):
        f = Fixture(5)
        try:
            b, _, _ = f.run(ids=[0,1,2,3])
            self.assertEqual(b["commit"]["body"]["phase"], "commit")
        finally:
            f.close()

    def test_no_commit_from_prepare_or_precommit(self):
        b, pq, pcq = self.f.run()
        for fake in (pq, pcq):
            changed = copy.deepcopy(b); changed["commit"] = fake
            with self.assertRaises(Refusal):
                verify_decision(changed, self.f.ctx, self.f.m)
            with self.assertRaises(ValueError):
                separate_verify(canonical(changed), canonical(self.f.m), canonical(self.f.ctx))

    def test_duplicate_signature_cannot_count_twice(self):
        b, _, _ = self.f.run()
        b["commit"]["votes"] = [b["commit"]["votes"][0]] * 3
        with self.assertRaises(Refusal):
            verify_decision(b, self.f.ctx, self.f.m)

    def test_nonmember_signature_rejected(self):
        b, _, _ = self.f.run()
        b["commit"]["votes"][0] = signature(keys_for(1, 100)[0], b["commit"]["body"])
        with self.assertRaises(Refusal):
            verify_decision(b, self.f.ctx, self.f.m)

    def test_every_signed_context_field_rejects_mutation(self):
        b, _, _ = self.f.run()
        for field in self.f.ctx:
            ctx = dict(self.f.ctx)
            ctx[field] = (ctx[field]+1 if type(ctx[field]) is int else "f"*64)
            with self.subTest(field=field), self.assertRaises((Refusal, TypeError)):
                verify_decision(b, ctx, self.f.m)

    def test_every_release_commitment_rejects_mutation(self):
        b, _, _ = self.f.run()
        for field in b["statement"]:
            x = copy.deepcopy(b)
            x["statement"][field] = 999 if field == "retention_height" else "f"*64
            with self.subTest(field=field), self.assertRaises(Refusal):
                verify_decision(x, self.f.ctx, self.f.m)

    def test_signature_tamper_both_readers(self):
        b, _, _ = self.f.run()
        b["commit"]["votes"][0]["signature"] = "00"*64
        with self.assertRaises(Refusal):
            verify_decision(b, self.f.ctx, self.f.m)
        with self.assertRaises(Exception):
            separate_verify(canonical(b), canonical(self.f.m), canonical(self.f.ctx))

    def test_double_prepare_refused_and_first_vote_retained(self):
        s = self.f.statement(); p, da = self.f.propose(1, s)
        first = self.f.nodes[0].prepare(p, b"candidate A")
        s2 = self.f.statement(b"candidate B"); da2 = self.f.da(s2, b"candidate B")
        p2 = proposal(self.f.keys[0], self.f.ctx, self.f.m, 1, p["body"]["reports"], s2, da2)
        with self.assertRaisesRegex(Refusal, "DOUBLE_SIGN"):
            self.f.nodes[0].prepare(p2, b"candidate B")
        self.assertEqual(first, self.f.nodes[0].prepare(p, b"candidate A"))

    def test_locked_replica_rejects_conflicting_proposal(self):
        b, _, _ = self.f.run(decide=False)
        s = self.f.statement(b"candidate B"); da = self.f.da(s, b"candidate B")
        for r in self.f.nodes:
            r.new_view(2)
        # Deliberately lying reports isolate the local lock check, not a <=f schedule.
        reports = ordered([signature(k, dict(context=identity(self.f.ctx), view=2, phase="new_view", high=None)) for k in self.f.keys])
        p = proposal(self.f.keys[1], self.f.ctx, self.f.m, 2, reports, s, da)
        with self.assertRaisesRegex(Refusal, "LOCKED"):
            self.f.nodes[0].prepare(p, b"candidate B")

    def test_higher_view_reports_repropose_known_value(self):
        b, _, _ = self.f.run(decide=False)
        b2, _, _ = self.f.run(view=2)
        self.assertEqual(identity(b["statement"]), identity(b2["statement"]))

    def test_leader_cannot_ignore_highest_qc(self):
        self.f.run(decide=False)
        with self.assertRaisesRegex(Refusal, "HIGHEST_QC_PROPOSAL"):
            self.f.propose(2, self.f.statement(b"candidate B"), b"candidate B")

    def test_wrong_leader_refused(self):
        s = self.f.statement(); p, _ = self.f.propose(1, s)
        p = signature(self.f.keys[1], p["body"])
        with self.assertRaisesRegex(Refusal, "LEADER"):
            self.f.nodes[0].prepare(p, b"candidate A")

    def test_unavailable_or_wrong_artifact_refuses_before_vote(self):
        s = self.f.statement(); p, _ = self.f.propose(1, s)
        for material in (b"wrong", None):
            with self.assertRaises(Refusal):
                self.f.nodes[0].prepare(p, material)
        rows = self.f.nodes[0].db.execute("SELECT slot FROM outbox WHERE slot LIKE '%/prepare/%'").fetchall()
        self.assertEqual(rows, [])

    def test_application_predicate_is_required_and_not_quality_claim(self):
        s = self.f.statement(); s["evaluation"] = "e"*64
        with self.assertRaisesRegex(Refusal, "APPLICATION_EVALUATION_PIN"):
            self.f.da(s)

    def test_view_regression_refused(self):
        self.f.nodes[0].new_view(4)
        with self.assertRaises(Refusal):
            self.f.nodes[0].new_view(3)

    def test_phase_predecessor_required(self):
        b, pq, pcq = self.f.run(decide=False)
        with self.assertRaises(Refusal):
            self.f.nodes[0].receive_qc(pcq, b["statement"], b"candidate A", b["availability"], pcq)

    def test_commit_can_arrive_after_view_change(self):
        b, _, _ = self.f.run(decide=False)
        for r in self.f.nodes:
            r.new_view(5)
            self.assertEqual(r.receive_qc(b["commit"], b["statement"], b"candidate A", b["availability"]), b)

    def test_process_cut_after_persist_before_send_preserves_vote(self):
        s = self.f.statement(); p, _ = self.f.propose(1, s)
        r = self.f.nodes[0]; r.fault = "after_commit"
        with self.assertRaises(Crash):
            r.prepare(p, b"candidate A")
        r.close()
        self.f.nodes[0] = Replica(Path(self.f.tmp.name)/"0", self.f.m, self.f.ctx, self.f.keys[0], local_application)
        self.assertEqual(self.f.nodes[0].prepare(p, b"candidate A")["body"]["phase"], "prepare")

    def test_process_cut_before_commit_leaves_no_vote(self):
        s = self.f.statement(); p, _ = self.f.propose(1, s)
        r = self.f.nodes[0]; r.fault = "before_commit"
        with self.assertRaises(Crash):
            r.prepare(p, b"candidate A")
        r.fault = None
        self.assertEqual(r.db.execute("SELECT COUNT(*) FROM outbox WHERE slot LIKE '%/prepare/%'").fetchone()[0], 0)

    def test_actual_process_exit_before_and_after_sql_commit(self):
        for cut, expected, count in (("exit_before_commit",79,0), ("exit_after_commit",80,1)):
            with tempfile.TemporaryDirectory() as directory:
                setup = dict(m=self.f.m, c=self.f.ctx, seed=self.f.keys[0].private_bytes_raw().hex())
                code = ('import json,sys; from protocol import *; x=json.loads(sys.argv[1]); '
                        'r=Replica(sys.argv[2],x["m"],x["c"],Ed25519PrivateKey.from_private_bytes(bytes.fromhex(x["seed"])),lambda s,a:None); '
                        'r.fault=sys.argv[3]; r.new_view(1)')
                out = subprocess.run([sys.executable,"-c",code,json.dumps(setup),str(Path(directory)/"state"),cut],
                                     cwd=Path(__file__).parent, timeout=10, capture_output=True)
                self.assertEqual(out.returncode, expected, out.stderr)
                r = Replica(Path(directory)/"state",self.f.m,self.f.ctx,self.f.keys[0],local_application)
                try:
                    self.assertEqual(r.db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0], count)
                    self.assertEqual(r.new_view(1)["body"]["view"], 1)
                finally:
                    r.close()

    def test_lock_and_high_qc_survive_reopen(self):
        self.f.run(decide=False)
        old = self.f.nodes[0].state(); self.f.nodes[0].close()
        self.f.nodes[0] = Replica(Path(self.f.tmp.name)/"0",self.f.m,self.f.ctx,self.f.keys[0],local_application)
        self.assertEqual(old, self.f.nodes[0].state())
        self.assertIsNotNone(self.f.nodes[0].new_view(2)["body"]["high"])

    def test_single_owner_lock(self):
        with self.assertRaisesRegex(Refusal, "STORE_ALREADY_OWNED"):
            Replica(Path(self.f.tmp.name)/"0",self.f.m,self.f.ctx,self.f.keys[0],local_application)

    def test_next_height_changes_parent_and_rejects_replay(self):
        b, _, _ = self.f.run()
        contexts = [r.advance() for r in self.f.nodes]
        self.assertTrue(all(c == contexts[0] for c in contexts))
        self.assertEqual(contexts[0]["parent"], identity(b["statement"]))
        with self.assertRaises(Refusal):
            self.f.nodes[0].receive_qc(b["commit"],b["statement"],b"candidate A",b["availability"])
        self.f.ctx = contexts[0]
        b2, _, _ = self.f.run(artifact=b"candidate B")
        self.assertEqual(b2["context"]["height"], 2)

    def test_old_epoch_sealed_new_epoch_requires_two_quorums(self):
        new_keys = keys_for(5,100)
        new_members = members_for(new_keys,epoch=1)
        b, _, _ = self.f.run(next_committee=identity(new_members))
        for r in self.f.nodes:
            with self.assertRaisesRegex(Refusal,"EPOCH_SEALED"):
                r.advance()
        ctx = context(new_members,2,identity(b["statement"]),b["statement"]["model"])
        n = Fixture(5,epoch=1,ctx=ctx,offset=100)
        try:
            with self.assertRaisesRegex(Refusal,"EPOCH_PENDING"):
                n.nodes[0].new_view(1)
            acks = ordered([r.acknowledge_epoch(b,self.f.ctx,self.f.m,b"candidate A") for r in n.nodes])
            with self.assertRaises(Refusal):
                verify_handoff(b,self.f.ctx,self.f.m,new_members,acks[:3])
            for r in n.nodes:
                r.activate_epoch(b,self.f.ctx,self.f.m,acks)
            n.run(artifact=b"candidate B")
        finally:
            n.close()

    def test_handoff_wrong_epoch_manifest_refused(self):
        m = members_for(keys_for(4,100),epoch=1)
        b, _, _ = self.f.run(next_committee=identity(m))
        m["epoch"] = 2
        with self.assertRaises(Refusal):
            handoff_body(b,self.f.ctx,self.f.m,m)

    def test_noncanonical_duplicate_and_oversized_wire(self):
        for data in (b'{"a":1,"a":2}', b'{"a": 1}', b'{"a":NaN}', b'x'*(MAX_WIRE+1)):
            with self.assertRaises(Refusal):
                decode(data)

    def test_rotation_after_dropped_prepare(self):
        s = self.f.statement(); p, _ = self.f.propose(1,s)
        for r in self.f.nodes[:2]:
            r.prepare(p,b"candidate A")
        b, _, _ = self.f.run(2,artifact=b"candidate B")
        self.assertEqual(b["commit"]["body"]["view"],2)

    def test_missing_new_view_quorum_refused(self):
        s = self.f.statement(); p, da = self.f.propose(1,s)
        with self.assertRaises(Refusal):
            proposal(self.f.keys[0],self.f.ctx,self.f.m,1,p["body"]["reports"][:2],s,da)

    def test_replayed_new_view_refused(self):
        s = self.f.statement(); p, da = self.f.propose(1,s)
        with self.assertRaises(Refusal):
            proposal(self.f.keys[1],self.f.ctx,self.f.m,2,p["body"]["reports"],s,da)

    def test_small_order_member_refused(self):
        m=copy.deepcopy(self.f.m);m["members"][0]="01"+"00"*31;m["members"].sort()
        with self.assertRaises(Refusal):manifest(m)

    def test_noncanonical_scalar_rejected(self):
        from strict_signature import L
        b,_,_=self.f.run()
        v=b["commit"]["votes"][0]
        v["signature"]=v["signature"][:64]+L.to_bytes(32,"little").hex()
        with self.assertRaises(Refusal):verify_decision(b,self.f.ctx,self.f.m)
        with self.assertRaises(ValueError):separate_verify(canonical(b),canonical(self.f.m),canonical(self.f.ctx))

    def test_old_signature_domain_cannot_be_promoted(self):
        b,_,_=self.f.run()
        v=b["commit"]["votes"][0]
        v["signature"]=self.f.keys[0].sign(b"trnm.committee-finality.v1"+canonical(v["body"])).hex()
        with self.assertRaises(Refusal):verify_decision(b,self.f.ctx,self.f.m)

    def test_decision_cut_before_effect_is_recovered(self):
        b,_,_=self.f.run(decide=False)
        r=self.f.nodes[0];r.fault="after_commit"
        with self.assertRaises(Crash):r.receive_qc(b["commit"],b["statement"],b"candidate A",b["availability"])
        r.close()
        self.f.nodes[0]=Replica(Path(self.f.tmp.name)/"0",self.f.m,self.f.ctx,self.f.keys[0],local_application)
        self.assertEqual(self.f.nodes[0].decision(),b)
        self.assertEqual(self.f.nodes[0].receive_qc(b["commit"],b["statement"],b"candidate A",b["availability"]),b)

    def test_high_prepare_does_not_regress(self):
        b,pq,pcq=self.f.run(decide=False)
        body=vote_body(self.f.ctx,10,"prepare",identity(b["statement"]))
        future=certificate(self.f.ctx,10,"prepare",body["value"],ordered([signature(k,body) for k in self.f.keys]),self.f.m)
        r=self.f.nodes[0]
        self.assertIsNone(r.receive_qc(future,b["statement"],b"candidate A",b["availability"]))
        r.receive_qc(pcq,b["statement"],b"candidate A",b["availability"],pq)
        self.assertEqual(r.state()["high"]["body"]["view"],10)

    def test_standalone_reader_cli(self):
        b, _, _ = self.f.run()
        root = Path(self.f.tmp.name)
        for name,obj in (("bundle",b),("committee",self.f.m),("context",self.f.ctx)):
            (root/name).write_bytes(canonical(obj))
        out = subprocess.run([sys.executable,str(Path(__file__).with_name("verify_certificate.py")),
                              "--bundle",str(root/"bundle"),"--committee",str(root/"committee"),"--context",str(root/"context")],
                             capture_output=True,timeout=10)
        self.assertEqual(out.returncode,0,out.stderr)
        self.assertFalse(json.loads(out.stdout)["production_activation"])

if __name__ == "__main__":
    unittest.main()
