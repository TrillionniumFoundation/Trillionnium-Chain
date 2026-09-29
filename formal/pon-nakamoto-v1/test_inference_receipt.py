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
if __name__=='__main__':unittest.main(verbosity=2)
