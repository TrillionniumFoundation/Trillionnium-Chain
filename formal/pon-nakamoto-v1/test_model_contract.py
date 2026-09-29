"""Remote-host integer inference matches the already implemented model math."""
import copy,json,tempfile,unittest
from pathlib import Path
from contract_wire import canonical,H
from ledger import FAMILY
from model_contract import load_model,infer,DIM,CLASSES

class PublicModelContractTests(unittest.TestCase):
    def model(self):
        base=[[0]*DIM for _ in range(3)];router=copy.deepcopy(base)
        deltas=[copy.deepcopy(base)for _ in range(3)]
        base[1][0]=2;router[2][0]=1;deltas[2][2][0]=3
        return dict(schema='hepta-source-owner-linear-256-v1',family=FAMILY.hex(),scale=1024,source='public-fixture',base=base,router=router,deltas=deltas,feature='signed-token-hash-256-clipped8-plus-bias-v1',classes=CLASSES)
    def test_integer_prediction_and_lowest_index_ties(self):
        row=[0]*DIM;row[0]=1;row[-1]=8
        self.assertEqual(infer(self.model(),[row]),[2])
        row[0]=0;self.assertEqual(infer(self.model(),[row]),[0])
    def test_expected_hash_and_shapes_are_checked_before_inference(self):
        with tempfile.TemporaryDirectory()as d:
            p=Path(d)/'model';raw=canonical(self.model());p.write_bytes(raw)
            self.assertEqual(load_model(p,H('artifact',raw)),self.model())
            with self.assertRaisesRegex(ValueError,'ARTIFACT_IDENTITY'):load_model(p,bytes(32))
            broken=self.model();broken['deltas'][0]=False;p.write_bytes(canonical(broken))
            with self.assertRaisesRegex(ValueError,'SHAPE'):load_model(p)
    def test_input_shape_type_batch_and_ranges_are_bounded(self):
        for rows in [[],[[0]*256],[[True]*DIM],[[9]*DIM],[[0]*DIM]*65]:
            with self.subTest(rows=len(rows)),self.assertRaises(ValueError):infer(self.model(),rows)
    def test_numpy_and_scalar_integer_outputs_match(self):
        from experiments.model_loop import predict
        rows=[]
        for n in range(20):rows.append([n%17-8]+[0]*(DIM-2)+[8])
        self.assertEqual(infer(self.model(),rows),predict(self.model(),rows).tolist())

if __name__=='__main__':unittest.main(verbosity=2)
