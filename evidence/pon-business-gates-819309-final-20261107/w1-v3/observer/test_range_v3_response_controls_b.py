import importlib.util,sys,unittest
from pathlib import Path
sys.dont_write_bytecode=True
p=Path("/home/qian-qi/throughput-final-ci-observation-20261107/read_w1_range_v3_819_b.py")
s=importlib.util.spec_from_file_location("range_reader",p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class RangeResponseControls(unittest.TestCase):
 def raw(self,status="206 Partial Content",rng=None,length=None,extra="",eol="\n"):
  return eol.join(["HTTP/2.0 "+status,"Content-Range: "+(rng or m.EXPECTED_RANGE),"Content-Length: "+str(m.TAIL if length is None else length),extra,""]).encode()
 def valid(self,**kw):
  x=m.parse_headers(self.raw(**kw));m.validate_headers(x);return x
 def test_exact_206_lf(self):self.assertEqual(self.valid()["status"],206)
 def test_exact_206_crlf(self):self.assertEqual(self.valid(eol="\r\n")["status"],206)
 def test_full_200_is_rejected(self):
  with self.assertRaisesRegex(ValueError,"STATUS"):self.valid(status="200 OK")
 def test_wrong_range_start_is_rejected(self):
  with self.assertRaisesRegex(ValueError,"RANGE"):self.valid(rng=f"bytes 0-{m.TOTAL-1}/{m.TOTAL}")
 def test_wrong_range_end_is_rejected(self):
  with self.assertRaisesRegex(ValueError,"RANGE"):self.valid(rng=f"bytes {m.START}-{m.TOTAL-2}/{m.TOTAL}")
 def test_wrong_total_is_rejected(self):
  with self.assertRaisesRegex(ValueError,"RANGE"):self.valid(rng=f"bytes {m.START}-{m.TOTAL-1}/{m.TOTAL+1}")
 def test_duplicate_range_is_rejected(self):
  with self.assertRaisesRegex(ValueError,"DUPLICATE"):self.valid(extra="Content-Range: "+m.EXPECTED_RANGE)
 def test_wrong_content_length_is_rejected(self):
  with self.assertRaisesRegex(ValueError,"LENGTH"):self.valid(length=m.TAIL+1)
 def test_encoded_bytes_are_rejected(self):
  with self.assertRaisesRegex(ValueError,"ENCODING"):self.valid(extra="Content-Encoding: gzip")
 def test_body_over_declared_tail_is_rejected(self):
  m.check_body_size(m.TAIL)
  with self.assertRaises(ValueError):m.check_body_size(m.TAIL+1)
 def test_body_over_four_mib_is_rejected(self):
  with self.assertRaisesRegex(ValueError,"4MIB"):m.check_body_size(m.MAX_BODY+1)
 def test_signed_url_is_not_retained_in_diagnostics(self):
  value=m.clean("Get https://storage.example/blob?sig=secret: error\nAuthorization: Bearer sensitive")
  self.assertNotIn("sig=secret",value);self.assertNotIn("sensitive",value)
if __name__=="__main__":unittest.main(verbosity=2)
