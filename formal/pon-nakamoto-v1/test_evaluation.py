import unittest
from evaluation import *
class ModelGateTests(unittest.TestCase):
    def test_stronger_single_control_not_weak_base_is_selected(self):
        rows=[{'id':str(i),'label':i%2,'source_group':str(i)}for i in range(40)];labels=[r['label']for r in rows]
        name,_=select_reference(rows,{'current':[0]*40,'best_single':labels,'mean_merge':[1]*40,'pooled':[0]*40});self.assertEqual(name,'best_single')
    def test_snippets_from_one_file_do_not_become_independent_samples(self):
        rows=[{'id':str(i),'label':1,'source_group':'one-file'}for i in range(100)]
        result=assess(rows,[1]*100,[0]*100);self.assertEqual(result['clusters'],1);self.assertFalse(result['cluster_gate'])
    def test_improving_over_base_but_losing_to_control_is_not_rewarded(self):
        rows=[{'id':str(i),'label':1,'source_group':str(i)}for i in range(40)]
        result=assess(rows,[1]*30+[0]*10,[1]*40);self.assertFalse(result['cluster_gate']);self.assertEqual(result['exploratory_score'],0)
    def test_positive_cluster_result_does_not_mint_future_acceptance(self):
        rows=[{'id':str(i),'label':1,'source_group':str(i)}for i in range(40)]
        result=assess(rows,[1]*40,[0]*40,future_window=True);self.assertTrue(result['cluster_gate']);self.assertFalse(result['public_reward_eligible'])
    def test_duplicate_task_and_partition_overlap_reject(self):
        with self.assertRaisesRegex(ValueError,'DUPLICATE_TASK'):assess([{'id':'x','label':1,'source_group':'a'}]*2,[1,1],[0,0])
        with self.assertRaisesRegex(ValueError,'PARTITION_OVERLAP'):freeze_plan(source='source',train_ids=['a'],calibration_ids=['a'],eligible_future_after=1,model_hash='hash')
    def test_reference_cannot_silently_omit_a_control(self):
        with self.assertRaisesRegex(ValueError,'CONTROL_SET'):select_reference([{'id':'a','label':1,'source_group':'a'}],{'current':[0]})
if __name__=='__main__':unittest.main(verbosity=2)
