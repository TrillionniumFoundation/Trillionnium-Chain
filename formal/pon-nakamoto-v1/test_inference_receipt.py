import unittest
from inference_receipt import *
class InferenceBindingTests(unittest.TestCase):
    def setUp(self):
        self.fields={k:H(k).hex()for k in FIELDS-{'units','provider_nonce'}}
        self.fields.update(network=NETWORK.hex(),parameters=PARAMETER_HASH.hex(),units=1,provider_nonce=1)
    def test_every_service_identity_is_bound(self):
        raw=receipt(self.fields);digest=verify(raw,self.fields)
        for name in FIELDS:
            value=dict(self.fields);value[name]=2 if name in {'units','provider_nonce'}else H('changed',name.encode()).hex()
            with self.subTest(name=name),self.assertRaises(ValueError):verify(canonical(value),self.fields)
        self.assertEqual(len(digest),32)
    def test_duplicate_or_implicit_receipt_fields_reject(self):
        raw=receipt(self.fields)
        with self.assertRaises(ValueError):verify(raw+b' ',self.fields)
        with self.assertRaises(ValueError):receipt(dict(self.fields,authority=True))
        with self.assertRaises(ValueError):verify(raw,{})
    def test_expected_cost_nonce_and_returned_output_cannot_be_omitted(self):
        raw=receipt(self.fields)
        for field in ['units','provider_nonce','output']:
            expected=dict(self.fields);expected.pop(field)
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'RECEIPT_BINDING'):verify(raw,expected)
    def test_oversized_receipt_rejects_before_json(self):
        from unittest.mock import patch
        with patch('inference_receipt.json.loads')as decode:
            with self.assertRaisesRegex(ValueError,'RECEIPT_LIMIT'):verify(b' '*2049,self.fields)
            decode.assert_not_called()
    def test_expected_boolean_counter_alias_rejects(self):
        expected=dict(self.fields,units=True)
        with self.assertRaisesRegex(ValueError,'RECEIPT_COUNTER'):verify(receipt(self.fields),expected)
if __name__=='__main__':unittest.main(verbosity=2)
