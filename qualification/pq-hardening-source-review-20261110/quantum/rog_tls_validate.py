#!/usr/bin/env python3
"""Isolated real Linux TLS controls for da1374; no pushes or global defaults.

Run only on the authorized rog host through the durable HeptaRuntime channel.
The source repo is read only. The script creates one exclusive checkout and
retains every command's raw output. A repeated launch must reuse the runtime's
idempotency key; the script refuses an already existing destination.
"""
from pathlib import Path
import argparse
import base64
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time

BASIS = "da1374a200022bc14dc2bd325cc9ba29dbcd24ab"
SOURCE = Path("/home/qian-qi/work/chain-cell-native-shard-674c72-20261110-publish")
BASE = Path("/home/qian-qi/work/chain-pq-0c8e-linux-20261110")
REPO = BASE / "source"
ORIGINAL_BLOBS = {
    "trillionnium/crates/trnm-pon-node/src/ingress/pq_network.rs": "68d5724a307fc16f43f0525b7ff76a0e6dbf4f48",
    "trillionnium/crates/trnm-pon-node/src/ingress/pq_network/canonical_tests.rs": "2882767d02ed8be8ceacfb974e2626ee248e623a",
    "trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/context.rs": "0da88394398edde4f52e7e5e81fc27f539b447b9",
    "trillionnium/crates/trnm-pon-node/src/ingress/pq_network/tls/tests.rs": "f9ceb93784bb5d376a5a61551a3e89a9089167e8",
}
PATCH_HASHES = {
    "negative-controls-only.patch": "24f142a6fca0f25d8d525ef4fd22c3f0b03485bf484f17463d4959d37830082b",
    "exact-spki.patch": "939910be8e0941fae8f5431d3977de0182a82bcfeda255888e87648c0c9e90e8",
}
PATCH_DATA = {'negative-controls-only.patch': 'LS0tIGEvdHJpbGxpb25uaXVtL2NyYXRlcy90cm5tLXBvbi1ub2RlL3NyYy9pbmdyZXNzL3BxX25ldHdvcmsvY2Fub25pY2FsX3Rlc3RzLnJzCisrKyBiL3RyaWxsaW9ubml1bS9jcmF0ZXMvdHJubS1wb24tbm9kZS9zcmMvaW5ncmVzcy9wcV9uZXR3b3JrL2Nhbm9uaWNhbF90ZXN0cy5ycwpAQCAtMzksNiArMzksMjkgQEAKICAgICAgICAgLnVud3JhcCgpLAogICAgICk7CiAgICAgKHNldHRpbmdzLCBwb2xpY3kpCit9CisKKyNbdGVzdF0KK2ZuIHBxX2NsaWVudF9yZXF1aXJlc19jb21wbGV0ZV9rZXlfcGluX2FmdGVyX2lkZW50aXR5X2xvb2t1cCgpIHsKKyAgICBsZXQgKF8sIG11dCBwb2xpY3kpID0gc2V0dXAoKTsKKyAgICBhc3NlcnQhKFBxQ2xpZW50OjpuZXcocG9saWN5LmNsb25lKCksIGtleSg3MikpLmlzX29rKCkpOworICAgIGxldCBzdWJzdGl0dXRlZCA9IGtleSg3Myk7CisgICAgLy8gQ29uZGl0aW9uYWwgYWxpYXMgY29udHJvbCwgbm90IGEgY29uc3RydWN0ZWQgU0hBLTI1NiBjb2xsaXNpb246IHJldGFpbgorICAgIC8vIHRoZSBzZWxlY3RlZCBpZGVudGl0eSBpbmRleCBidXQgcGxhY2UgYSBkaWZmZXJlbnQgcmVhbCBNTC1EU0EgdmVyaWZpZXIKKyAgICAvLyBiZWhpbmQgaXQuIE1lbWJlcnNoaXAgYWxvbmUgbXVzdCBub3QgcmVwbGFjZSB0aGUgaW5kZXBlbmRlbnQgZnVsbCBwaW4uCisgICAgQXJjOjpnZXRfbXV0KCZtdXQgcG9saWN5KS51bndyYXAoKS5wZWVycy5pbnNlcnQoCisgICAgICAgIGtleSg3MikucHVibGljX2tleV9pZCgpLAorICAgICAgICBQcU5hdGl2ZVZlcmlmaWVyOjpmcm9tX3Bpbm5lZF9zcGtpKAorICAgICAgICAgICAgc3Vic3RpdHV0ZWQucHVibGljX3Nwa2koKSwKKyAgICAgICAgICAgIHN1YnN0aXR1dGVkLnB1YmxpY19rZXlfaWQoKSwKKyAgICAgICAgKQorICAgICAgICAudW53cmFwKCksCisgICAgKTsKKyAgICBsZXQgZXJyb3IgPSBtYXRjaCBQcUNsaWVudDo6bmV3KHBvbGljeSwga2V5KDcyKSkgeworICAgICAgICBPayhfKSA9PiBwYW5pYyEoImFuIGlkZW50aXR5IGluZGV4IGNhbm5vdCByZXBsYWNlIHRoZSBjb21wbGV0ZSBjbGllbnQga2V5IHBpbiIpLAorICAgICAgICBFcnIoZXJyb3IpID0+IGVycm9yLAorICAgIH07CisgICAgYXNzZXJ0X2VxIShlcnJvci50b19zdHJpbmcoKSwgIlBRX05FVFdPUktfVU5LTk9XTl9QRUVSIik7CiB9CiAKICNbdGVzdF0KLS0tIGEvdHJpbGxpb25uaXVtL2NyYXRlcy90cm5tLXBvbi1ub2RlL3NyYy9pbmdyZXNzL3BxX25ldHdvcmsvdGxzL3Rlc3RzLnJzCisrKyBiL3RyaWxsaW9ubml1bS9jcmF0ZXMvdHJubS1wb24tbm9kZS9zcmMvaW5ncmVzcy9wcV9uZXR3b3JrL3Rscy90ZXN0cy5ycwpAQCAtMzIsNiArMzIsMTI2IEBACiBmbiBmaW5pc2goc3RvcDogQXJjPEF0b21pY0Jvb2w+LCBoYW5kbGU6IHRocmVhZDo6Sm9pbkhhbmRsZTxQcU5ldHdvcmtNZXRyaWNzPikgLT4gUHFOZXR3b3JrTWV0cmljcyB7CiAgICAgc3RvcC5zdG9yZSh0cnVlLCBPcmRlcmluZzo6UmVsZWFzZSk7CiAgICAgaGFuZGxlLmpvaW4oKS51bndyYXAoKQorfQorCisjW3Rlc3RdCitmbiB0bHNfbG9jYWxfaWRlbnRpdHlfcmVxdWlyZXNfY29tcGxldGVfa2V5X3Bpbl9mb3JfYm90aF9yb2xlcygpIHsKKyAgICBsZXQgZml4dHVyZSA9IEZpeHR1cmU6Om5ldygpOworICAgIGZvciBzZXJ2ZXIgaW4gW2ZhbHNlLCB0cnVlXSB7CisgICAgICAgIGxldCBtdXQgcG9saWN5ID0gZml4dHVyZS5wb2xpY3lfZm9yX3NlcnZlcl9uYW1lKCJsb2NhbGhvc3QiKTsKKyAgICAgICAgbGV0IGlkZW50aXR5ID0gaWYgc2VydmVyIHsgJmZpeHR1cmUuc2VydmVyIH0gZWxzZSB7ICZmaXh0dXJlLnBlZXIgfTsKKyAgICAgICAgbGV0IGxvY2FsX2lkID0gaWRlbnRpdHkuc2lnbmVyKCkucHVibGljX2tleV9pZCgpOworICAgICAgICBsZXQgc3Vic3RpdHV0ZSA9IGZpeHR1cmUub3RoZXIuc2lnbmVyKCk7CisgICAgICAgIGxldCB2ZXJpZmllciA9IFBxTmF0aXZlVmVyaWZpZXI6OmZyb21fcGlubmVkX3Nwa2koCisgICAgICAgICAgICBzdWJzdGl0dXRlLnB1YmxpY19zcGtpKCksCisgICAgICAgICAgICBzdWJzdGl0dXRlLnB1YmxpY19rZXlfaWQoKSwKKyAgICAgICAgKQorICAgICAgICAudW53cmFwKCk7CisgICAgICAgIC8vIERlbGliZXJhdGVseSBtb2RlbCBhbiBpZGVudGl0eS1pbmRleCBhbGlhcyB3aXRob3V0IGNsYWltaW5nIHRvIGhhdmUKKyAgICAgICAgLy8gZm91bmQgYSBoYXNoIGNvbGxpc2lvbiBvciBjaGFuZ2luZyBhbnkgY2VydGlmaWNhdGUvc2lnbmF0dXJlIGJ5dGVzLgorICAgICAgICBsZXQgb3duZXIgPSBBcmM6OmdldF9tdXQoJm11dCBwb2xpY3kpLnVud3JhcCgpOworICAgICAgICBpZiBzZXJ2ZXIgeworICAgICAgICAgICAgb3duZXIuc2VydmVyID0gdmVyaWZpZXI7CisgICAgICAgIH0gZWxzZSB7CisgICAgICAgICAgICBvd25lci5wZWVycy5pbnNlcnQobG9jYWxfaWQsIHZlcmlmaWVyKTsKKyAgICAgICAgfQorICAgICAgICBsZXQgcmVzdWx0ID0gY29udGV4dDo6VGxzQ29udGV4dDo6bmV3KHBvbGljeSwgbG9jYWxfaWQsIGlkZW50aXR5LnRscygmZml4dHVyZS5jYSksIHNlcnZlcik7CisgICAgICAgIGxldCBlcnJvciA9IG1hdGNoIHJlc3VsdCB7CisgICAgICAgICAgICBPayhfKSA9PiBwYW5pYyEoIlRMUyBsb2NhbCBrZXkgYWRtaXNzaW9uIHVzZWQgb25seSB0aGUgaWRlbnRpdHkgaW5kZXgiKSwKKyAgICAgICAgICAgIEVycihlcnJvcikgPT4gZXJyb3IsCisgICAgICAgIH07CisgICAgICAgIGFzc2VydF9lcSEoZXJyb3IudG9fc3RyaW5nKCksICJQUV9UTFNfTE9DQUxfUElOIik7CisgICAgfQorfQorCisjW3Rlc3RdCitmbiBhY3R1YWxfdGxzX3BlZXJfaWRlbnRpdHlfYWxpYXNfcmVmdXNlc19iZWZvcmVfYXBwbGljYXRpb25fZGlzcGF0Y2hfaW5fYm90aF9kaXJlY3Rpb25zKCkgeworICAgIGZvciBjbGllbnRfY2hlY2tzX3NlcnZlciBpbiBbZmFsc2UsIHRydWVdIHsKKyAgICAgICAgbGV0IGZpeHR1cmUgPSBGaXh0dXJlOjpuZXcoKTsKKyAgICAgICAgbGV0IG11dCBzZWxlY3RlZCA9IGZpeHR1cmUucG9saWN5X2Zvcl9zZXJ2ZXJfbmFtZSgibG9jYWxob3N0Iik7CisgICAgICAgIGxldCBzdWJzdGl0dXRlID0gZml4dHVyZS5vdGhlci5zaWduZXIoKTsKKyAgICAgICAgbGV0IHZlcmlmaWVyID0gUHFOYXRpdmVWZXJpZmllcjo6ZnJvbV9waW5uZWRfc3BraSgKKyAgICAgICAgICAgIHN1YnN0aXR1dGUucHVibGljX3Nwa2koKSwKKyAgICAgICAgICAgIHN1YnN0aXR1dGUucHVibGljX2tleV9pZCgpLAorICAgICAgICApCisgICAgICAgIC51bndyYXAoKTsKKyAgICAgICAgLy8gVGhlIHJlYWwgVExTIGV4Y2hhbmdlIGJlbG93IHVzZXMgdmFsaWQgTUwtRFNBIGNlcnRpZmljYXRlcywgbXV0dWFsCisgICAgICAgIC8vIGF1dGhlbnRpY2F0aW9uIGFuZCB0aGUgcGlubmVkIENBLiBUaGlzIHByaXZhdGUgbXV0YXRpb24gc3VwcGxpZXMgdGhlCisgICAgICAgIC8vIGNvbmRpdGlvbmFsIGlkZW50aXR5IGFsaWFzOyBpdCBpcyBub3QgYW4gb2JzZXJ2ZWQgU0hBLTI1NiBjb2xsaXNpb24uCisgICAgICAgIGxldCBvd25lciA9IEFyYzo6Z2V0X211dCgmbXV0IHNlbGVjdGVkKS51bndyYXAoKTsKKyAgICAgICAgaWYgY2xpZW50X2NoZWNrc19zZXJ2ZXIgeworICAgICAgICAgICAgb3duZXIuc2VydmVyID0gdmVyaWZpZXI7CisgICAgICAgIH0gZWxzZSB7CisgICAgICAgICAgICBvd25lci5wZWVycy5pbnNlcnQoZml4dHVyZS5wZWVyLnNpZ25lcigpLnB1YmxpY19rZXlfaWQoKSwgdmVyaWZpZXIpOworICAgICAgICB9CisgICAgICAgIGxldCAoY2xpZW50LCBzZXJ2ZXIpID0gaWYgY2xpZW50X2NoZWNrc19zZXJ2ZXIgeworICAgICAgICAgICAgKAorICAgICAgICAgICAgICAgIFBxVGxzQ2xpZW50OjpuZXcoCisgICAgICAgICAgICAgICAgICAgIHNlbGVjdGVkLAorICAgICAgICAgICAgICAgICAgICBmaXh0dXJlLnBlZXIuc2lnbmVyKCksCisgICAgICAgICAgICAgICAgICAgIGZpeHR1cmUucGVlci50bHMoJmZpeHR1cmUuY2EpLAorICAgICAgICAgICAgICAgICkKKyAgICAgICAgICAgICAgICAudW53cmFwKCksCisgICAgICAgICAgICAgICAgZml4dHVyZS5zZXJ2ZXIoKSwKKyAgICAgICAgICAgICkKKyAgICAgICAgfSBlbHNlIHsKKyAgICAgICAgICAgICgKKyAgICAgICAgICAgICAgICBmaXh0dXJlLmNsaWVudCgpLAorICAgICAgICAgICAgICAgIFBxVGxzU2VydmVyOjpuZXcoCisgICAgICAgICAgICAgICAgICAgIHNlbGVjdGVkLAorICAgICAgICAgICAgICAgICAgICBmaXh0dXJlLnNlcnZlci5zaWduZXIoKSwKKyAgICAgICAgICAgICAgICAgICAgZml4dHVyZS5zZXJ2ZXIudGxzKCZmaXh0dXJlLmNhKSwKKyAgICAgICAgICAgICAgICApCisgICAgICAgICAgICAgICAgLnVud3JhcCgpLAorICAgICAgICAgICAgKQorICAgICAgICB9OworICAgICAgICBsZXQgZGlyZWN0b3J5ID0gdGVtcGZpbGU6OnRlbXBkaXIoKS51bndyYXAoKTsKKyAgICAgICAgbGV0IG5vZGUgPSBOb2RlOjpvcGVuX3dpdGhfcHFfbmV0d29yaygKKyAgICAgICAgICAgIGRpcmVjdG9yeS5wYXRoKCksCisgICAgICAgICAgICBmaXh0dXJlLnNldHRpbmdzLmNsb25lKCksCisgICAgICAgICAgICAxLAorICAgICAgICAgICAgJmZpeHR1cmUucG9saWN5LAorICAgICAgICApCisgICAgICAgIC51bndyYXAoKTsKKyAgICAgICAgbGV0IHByZXBhcmVkID0gY2xpZW50CisgICAgICAgICAgICAucHJlcGFyZSgxLCBjcmF0ZTo6aW5ncmVzczo6bm93KCkudW53cmFwKCkgKyAzMCwgUmVxdWVzdDo6SGVhZCkKKyAgICAgICAgICAgIC51bndyYXAoKTsKKyAgICAgICAgbGV0IGxpc3RlbmVyID0gVGNwTGlzdGVuZXI6OmJpbmQoIjEyNy4wLjAuMTowIikudW53cmFwKCk7CisgICAgICAgIGxpc3RlbmVyLnNldF9ub25ibG9ja2luZyh0cnVlKS51bndyYXAoKTsKKyAgICAgICAgbGV0IGFkZHJlc3MgPSBsaXN0ZW5lci5sb2NhbF9hZGRyKCkudW53cmFwKCk7CisgICAgICAgIGxldCBkZWFkbGluZSA9IEluc3RhbnQ6Om5vdygpICsgRHVyYXRpb246OmZyb21fc2Vjcyg1KTsKKyAgICAgICAgbGV0IHdvcmtlciA9IHRocmVhZDo6c3Bhd24obW92ZSB8fCB7CisgICAgICAgICAgICBsZXQgb3duZXIgPSBNdXRleDo6bmV3KG5vZGUpOworICAgICAgICAgICAgLy8gQSBjbGllbnQgdGhhdCBleHBpcmVzIGJlZm9yZSBjb25uZWN0aW5nIG11c3Qgbm90IGxlYXZlIGpvaW4oKQorICAgICAgICAgICAgLy8gd2FpdGluZyBvbiBhbiB1bmJvdW5kZWQgYWNjZXB0LiBBY2NlcHQgYW5kIGhhbmRzaGFrZSBjb25zdW1lCisgICAgICAgICAgICAvLyB0aGUgc2FtZSBvcmlnaW5hbCBpbnRlcnZhbCwgaW5jbHVkaW5nIGV2ZXJ5IFdvdWxkQmxvY2sgcmV0cnkuCisgICAgICAgICAgICBsZXQgc3RyZWFtID0gKHx8IC0+IFJlc3VsdDxUY3BTdHJlYW0+IHsKKyAgICAgICAgICAgICAgICBsb29wIHsKKyAgICAgICAgICAgICAgICAgICAgY2hlY2tfbGl2ZV9yZXF1ZXN0KGRlYWRsaW5lLCBOb25lKT87CisgICAgICAgICAgICAgICAgICAgIG1hdGNoIGxpc3RlbmVyLmFjY2VwdCgpIHsKKyAgICAgICAgICAgICAgICAgICAgICAgIE9rKChzdHJlYW0sIF8pKSA9PiByZXR1cm4gT2soc3RyZWFtKSwKKyAgICAgICAgICAgICAgICAgICAgICAgIEVycihlcnJvcikgaWYgZXJyb3Iua2luZCgpID09IHN0ZDo6aW86OkVycm9yS2luZDo6V291bGRCbG9jayA9PiB7CisgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhyZWFkOjpzbGVlcChEdXJhdGlvbjo6ZnJvbV9taWxsaXMoMikpOworICAgICAgICAgICAgICAgICAgICAgICAgfQorICAgICAgICAgICAgICAgICAgICAgICAgRXJyKGVycm9yKSA9PiByZXR1cm4gRXJyKGVycm9yLmludG8oKSksCisgICAgICAgICAgICAgICAgICAgIH0KKyAgICAgICAgICAgICAgICB9CisgICAgICAgICAgICB9KSgpOworICAgICAgICAgICAgbGV0IHJlc3VsdCA9IHN0cmVhbS5hbmRfdGhlbih8c3RyZWFtfCBzZXJ2ZXIuY29ubmVjdGlvbihzdHJlYW0sICZvd25lciwgZGVhZGxpbmUpKTsKKyAgICAgICAgICAgIChyZXN1bHQsIG93bmVyLmludG9faW5uZXIoKS51bndyYXAoKSkKKyAgICAgICAgfSk7CisgICAgICAgIGxldCBjbGllbnRfcmVzdWx0ID0gY2xpZW50LmV4Y2hhbmdlKGFkZHJlc3MsIHByZXBhcmVkLndpcmUoKSwgZGVhZGxpbmUpOworICAgICAgICBsZXQgKHNlcnZlcl9yZXN1bHQsIG5vZGUpID0gd29ya2VyLmpvaW4oKS51bndyYXAoKTsKKyAgICAgICAgbGV0IGVycm9yID0gaWYgY2xpZW50X2NoZWNrc19zZXJ2ZXIgeworICAgICAgICAgICAgY2xpZW50X3Jlc3VsdC5leHBlY3RfZXJyKCJUTFMgY2xpZW50IG11c3QgcmVqZWN0IGFuIGFsaWFzZWQgc2VydmVyIGtleSIpCisgICAgICAgIH0gZWxzZSB7CisgICAgICAgICAgICBzZXJ2ZXJfcmVzdWx0LmV4cGVjdF9lcnIoIlRMUyBzZXJ2ZXIgbXVzdCByZWplY3QgYW4gYWxpYXNlZCBjbGllbnQga2V5IikKKyAgICAgICAgfTsKKyAgICAgICAgYXNzZXJ0X2VxIShlcnJvci50b19zdHJpbmcoKSwgIlBRX1RMU19QRUVSX1BJTiIpOworICAgICAgICBsZXQgc3RhdHVzID0gbm9kZS5wcV9uZXR3b3JrX3N0YXR1cygmZml4dHVyZS5wb2xpY3kpLnVud3JhcCgpOworICAgICAgICBhc3NlcnRfZXEhKHN0YXR1c1sicmVjb3JkcyJdLCAwKTsKKyAgICAgICAgYXNzZXJ0X2VxIShzdGF0dXNbImluYm91bmRfc2lnbmF0dXJlX2F0dGVtcHRzIl0sIDApOworICAgIH0KIH0KIAogI1t0ZXN0XQo=', 'exact-spki.patch': 'LS0tIGEvdHJpbGxpb25uaXVtL2NyYXRlcy90cm5tLXBvbi1ub2RlL3NyYy9pbmdyZXNzL3BxX25ldHdvcmsucnMKKysrIGIvdHJpbGxpb25uaXVtL2NyYXRlcy90cm5tLXBvbi1ub2RlL3NyYy9pbmdyZXNzL3BxX25ldHdvcmsucnMKQEAgLTU2OCw3ICs1NjgsMTAgQEAKIGltcGwgUHFDbGllbnQgewogICAgIHB1YiBmbiBuZXcocG9saWN5OiBBcmM8UHFOZXR3b3JrUG9saWN5Piwgc2lnbmVyOiBQcU5hdGl2ZVNpZ25pbmdLZXkpIC0+IFJlc3VsdDxTZWxmPiB7CiAgICAgICAgIGVuc3VyZSgKLSAgICAgICAgICAgIHBvbGljeS5wZWVycy5jb250YWluc19rZXkoJnNpZ25lci5wdWJsaWNfa2V5X2lkKCkpLAorICAgICAgICAgICAgcG9saWN5CisgICAgICAgICAgICAgICAgLnBlZXJzCisgICAgICAgICAgICAgICAgLmdldCgmc2lnbmVyLnB1YmxpY19rZXlfaWQoKSkKKyAgICAgICAgICAgICAgICAuaXNfc29tZV9hbmQofHBpbm5lZHwgcGlubmVkLnB1YmxpY19zcGtpKCkgPT0gc2lnbmVyLnB1YmxpY19zcGtpKCkpLAogICAgICAgICAgICAgIlBRX05FVFdPUktfVU5LTk9XTl9QRUVSIiwKICAgICAgICAgKT87CiAgICAgICAgIE9rKFNlbGYgewotLS0gYS90cmlsbGlvbm5pdW0vY3JhdGVzL3Rybm0tcG9uLW5vZGUvc3JjL2luZ3Jlc3MvcHFfbmV0d29yay9jYW5vbmljYWxfdGVzdHMucnMKKysrIGIvdHJpbGxpb25uaXVtL2NyYXRlcy90cm5tLXBvbi1ub2RlL3NyYy9pbmdyZXNzL3BxX25ldHdvcmsvY2Fub25pY2FsX3Rlc3RzLnJzCkBAIC0zOSw2ICszOSwyOSBAQAogICAgICAgICAudW53cmFwKCksCiAgICAgKTsKICAgICAoc2V0dGluZ3MsIHBvbGljeSkKK30KKworI1t0ZXN0XQorZm4gcHFfY2xpZW50X3JlcXVpcmVzX2NvbXBsZXRlX2tleV9waW5fYWZ0ZXJfaWRlbnRpdHlfbG9va3VwKCkgeworICAgIGxldCAoXywgbXV0IHBvbGljeSkgPSBzZXR1cCgpOworICAgIGFzc2VydCEoUHFDbGllbnQ6Om5ldyhwb2xpY3kuY2xvbmUoKSwga2V5KDcyKSkuaXNfb2soKSk7CisgICAgbGV0IHN1YnN0aXR1dGVkID0ga2V5KDczKTsKKyAgICAvLyBDb25kaXRpb25hbCBhbGlhcyBjb250cm9sLCBub3QgYSBjb25zdHJ1Y3RlZCBTSEEtMjU2IGNvbGxpc2lvbjogcmV0YWluCisgICAgLy8gdGhlIHNlbGVjdGVkIGlkZW50aXR5IGluZGV4IGJ1dCBwbGFjZSBhIGRpZmZlcmVudCByZWFsIE1MLURTQSB2ZXJpZmllcgorICAgIC8vIGJlaGluZCBpdC4gTWVtYmVyc2hpcCBhbG9uZSBtdXN0IG5vdCByZXBsYWNlIHRoZSBpbmRlcGVuZGVudCBmdWxsIHBpbi4KKyAgICBBcmM6OmdldF9tdXQoJm11dCBwb2xpY3kpLnVud3JhcCgpLnBlZXJzLmluc2VydCgKKyAgICAgICAga2V5KDcyKS5wdWJsaWNfa2V5X2lkKCksCisgICAgICAgIFBxTmF0aXZlVmVyaWZpZXI6OmZyb21fcGlubmVkX3Nwa2koCisgICAgICAgICAgICBzdWJzdGl0dXRlZC5wdWJsaWNfc3BraSgpLAorICAgICAgICAgICAgc3Vic3RpdHV0ZWQucHVibGljX2tleV9pZCgpLAorICAgICAgICApCisgICAgICAgIC51bndyYXAoKSwKKyAgICApOworICAgIGxldCBlcnJvciA9IG1hdGNoIFBxQ2xpZW50OjpuZXcocG9saWN5LCBrZXkoNzIpKSB7CisgICAgICAgIE9rKF8pID0+IHBhbmljISgiYW4gaWRlbnRpdHkgaW5kZXggY2Fubm90IHJlcGxhY2UgdGhlIGNvbXBsZXRlIGNsaWVudCBrZXkgcGluIiksCisgICAgICAgIEVycihlcnJvcikgPT4gZXJyb3IsCisgICAgfTsKKyAgICBhc3NlcnRfZXEhKGVycm9yLnRvX3N0cmluZygpLCAiUFFfTkVUV09SS19VTktOT1dOX1BFRVIiKTsKIH0KIAogI1t0ZXN0XQotLS0gYS90cmlsbGlvbm5pdW0vY3JhdGVzL3Rybm0tcG9uLW5vZGUvc3JjL2luZ3Jlc3MvcHFfbmV0d29yay90bHMvY29udGV4dC5ycworKysgYi90cmlsbGlvbm5pdW0vY3JhdGVzL3Rybm0tcG9uLW5vZGUvc3JjL2luZ3Jlc3MvcHFfbmV0d29yay90bHMvY29udGV4dC5ycwpAQCAtMTE5LDggKzExOSwxMSBAQAogICAgICAgICAgICAgbWxfZHNhXzY1X2tleV9pZF9mcm9tX3Nwa2koJmxvY2FsX3Nwa2kpLm1hcF9lcnIoY3J5cHRvKT8gPT0gbG9jYWxfaWQKICAgICAgICAgICAgICAgICAmJiBpZiBzZXJ2ZXIgewogICAgICAgICAgICAgICAgICAgICBsb2NhbF9pZCA9PSBwb2xpY3kuc2VydmVyX2lkCisgICAgICAgICAgICAgICAgICAgICAgICAmJiBwb2xpY3kuc2VydmVyLnB1YmxpY19zcGtpKCkuYXNfc2xpY2UoKSA9PSBsb2NhbF9zcGtpLmFzX3NsaWNlKCkKICAgICAgICAgICAgICAgICB9IGVsc2UgewotICAgICAgICAgICAgICAgICAgICBwb2xpY3kucGVlcnMuY29udGFpbnNfa2V5KCZsb2NhbF9pZCkKKyAgICAgICAgICAgICAgICAgICAgcG9saWN5LnBlZXJzLmdldCgmbG9jYWxfaWQpLmlzX3NvbWVfYW5kKHxwaW5uZWR8IHsKKyAgICAgICAgICAgICAgICAgICAgICAgIHBpbm5lZC5wdWJsaWNfc3BraSgpLmFzX3NsaWNlKCkgPT0gbG9jYWxfc3BraS5hc19zbGljZSgpCisgICAgICAgICAgICAgICAgICAgIH0pCiAgICAgICAgICAgICAgICAgfSwKICAgICAgICAgICAgICJQUV9UTFNfTE9DQUxfUElOIiwKICAgICAgICAgKT87CkBAIC0yMTEsMTMgKzIxNCwyMCBAQAogICAgICAgICApPzsKICAgICAgICAgbGV0IHB1YmxpYyA9IGNlcnRpZmljYXRlLnB1YmxpY19rZXkoKS5tYXBfZXJyKGNyeXB0byk/OwogICAgICAgICBlbnN1cmUocHVibGljLmlzX2EoS2V5VHlwZTo6TUxfRFNBXzY1KSwgIlBRX1RMU19QRUVSX0tFWSIpPzsKLSAgICAgICAgbGV0IHBlZXIgPSBtbF9kc2FfNjVfa2V5X2lkX2Zyb21fc3BraSgmcHVibGljLnB1YmxpY19rZXlfdG9fZGVyKCkubWFwX2VycihjcnlwdG8pPykKLSAgICAgICAgICAgIC5tYXBfZXJyKGNyeXB0byk/OworICAgICAgICBsZXQgc3BraSA9IHB1YmxpYy5wdWJsaWNfa2V5X3RvX2RlcigpLm1hcF9lcnIoY3J5cHRvKT87CisgICAgICAgIGxldCBwZWVyID0gbWxfZHNhXzY1X2tleV9pZF9mcm9tX3Nwa2koJnNwa2kpLm1hcF9lcnIoY3J5cHRvKT87CisgICAgICAgIC8vIFRoZSBsZWdhY3kgU0hBLTI1NiBpZGVudGl0eSBvbmx5IGxvY2F0ZXMgdGhlIGluZGVwZW5kZW50IGZ1bGwga2V5CisgICAgICAgIC8vIHBpbi4gRXZlbiBhbiBpZGVudGlmaWVyIGFsaWFzIG11c3Qgbm90IHN1YnN0aXR1dGUgZGlmZmVyZW50IFRMUyBrZXkKKyAgICAgICAgLy8gbWF0ZXJpYWwgYmVmb3JlIGFwcGxpY2F0aW9uIGJ5dGVzIGVudGVyIHRoZSBlbmNyeXB0ZWQgY2hhbm5lbC4KICAgICAgICAgZW5zdXJlKAogICAgICAgICAgICAgaWYgc2VsZi5zZXJ2ZXIgewotICAgICAgICAgICAgICAgIHNlbGYucG9saWN5LnBlZXJzLmNvbnRhaW5zX2tleSgmcGVlcikKKyAgICAgICAgICAgICAgICBzZWxmLnBvbGljeQorICAgICAgICAgICAgICAgICAgICAucGVlcnMKKyAgICAgICAgICAgICAgICAgICAgLmdldCgmcGVlcikKKyAgICAgICAgICAgICAgICAgICAgLmlzX3NvbWVfYW5kKHxwaW5uZWR8IHBpbm5lZC5wdWJsaWNfc3BraSgpLmFzX3NsaWNlKCkgPT0gc3BraS5hc19zbGljZSgpKQogICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICAgICBwZWVyID09IHNlbGYucG9saWN5LnNlcnZlcl9pZAorICAgICAgICAgICAgICAgICAgICAmJiBzZWxmLnBvbGljeS5zZXJ2ZXIucHVibGljX3Nwa2koKS5hc19zbGljZSgpID09IHNwa2kuYXNfc2xpY2UoKQogICAgICAgICAgICAgfSwKICAgICAgICAgICAgICJQUV9UTFNfUEVFUl9QSU4iLAogICAgICAgICApPzsKLS0tIGEvdHJpbGxpb25uaXVtL2NyYXRlcy90cm5tLXBvbi1ub2RlL3NyYy9pbmdyZXNzL3BxX25ldHdvcmsvdGxzL3Rlc3RzLnJzCisrKyBiL3RyaWxsaW9ubml1bS9jcmF0ZXMvdHJubS1wb24tbm9kZS9zcmMvaW5ncmVzcy9wcV9uZXR3b3JrL3Rscy90ZXN0cy5ycwpAQCAtMzIsNiArMzIsMTI2IEBACiBmbiBmaW5pc2goc3RvcDogQXJjPEF0b21pY0Jvb2w+LCBoYW5kbGU6IHRocmVhZDo6Sm9pbkhhbmRsZTxQcU5ldHdvcmtNZXRyaWNzPikgLT4gUHFOZXR3b3JrTWV0cmljcyB7CiAgICAgc3RvcC5zdG9yZSh0cnVlLCBPcmRlcmluZzo6UmVsZWFzZSk7CiAgICAgaGFuZGxlLmpvaW4oKS51bndyYXAoKQorfQorCisjW3Rlc3RdCitmbiB0bHNfbG9jYWxfaWRlbnRpdHlfcmVxdWlyZXNfY29tcGxldGVfa2V5X3Bpbl9mb3JfYm90aF9yb2xlcygpIHsKKyAgICBsZXQgZml4dHVyZSA9IEZpeHR1cmU6Om5ldygpOworICAgIGZvciBzZXJ2ZXIgaW4gW2ZhbHNlLCB0cnVlXSB7CisgICAgICAgIGxldCBtdXQgcG9saWN5ID0gZml4dHVyZS5wb2xpY3lfZm9yX3NlcnZlcl9uYW1lKCJsb2NhbGhvc3QiKTsKKyAgICAgICAgbGV0IGlkZW50aXR5ID0gaWYgc2VydmVyIHsgJmZpeHR1cmUuc2VydmVyIH0gZWxzZSB7ICZmaXh0dXJlLnBlZXIgfTsKKyAgICAgICAgbGV0IGxvY2FsX2lkID0gaWRlbnRpdHkuc2lnbmVyKCkucHVibGljX2tleV9pZCgpOworICAgICAgICBsZXQgc3Vic3RpdHV0ZSA9IGZpeHR1cmUub3RoZXIuc2lnbmVyKCk7CisgICAgICAgIGxldCB2ZXJpZmllciA9IFBxTmF0aXZlVmVyaWZpZXI6OmZyb21fcGlubmVkX3Nwa2koCisgICAgICAgICAgICBzdWJzdGl0dXRlLnB1YmxpY19zcGtpKCksCisgICAgICAgICAgICBzdWJzdGl0dXRlLnB1YmxpY19rZXlfaWQoKSwKKyAgICAgICAgKQorICAgICAgICAudW53cmFwKCk7CisgICAgICAgIC8vIERlbGliZXJhdGVseSBtb2RlbCBhbiBpZGVudGl0eS1pbmRleCBhbGlhcyB3aXRob3V0IGNsYWltaW5nIHRvIGhhdmUKKyAgICAgICAgLy8gZm91bmQgYSBoYXNoIGNvbGxpc2lvbiBvciBjaGFuZ2luZyBhbnkgY2VydGlmaWNhdGUvc2lnbmF0dXJlIGJ5dGVzLgorICAgICAgICBsZXQgb3duZXIgPSBBcmM6OmdldF9tdXQoJm11dCBwb2xpY3kpLnVud3JhcCgpOworICAgICAgICBpZiBzZXJ2ZXIgeworICAgICAgICAgICAgb3duZXIuc2VydmVyID0gdmVyaWZpZXI7CisgICAgICAgIH0gZWxzZSB7CisgICAgICAgICAgICBvd25lci5wZWVycy5pbnNlcnQobG9jYWxfaWQsIHZlcmlmaWVyKTsKKyAgICAgICAgfQorICAgICAgICBsZXQgcmVzdWx0ID0gY29udGV4dDo6VGxzQ29udGV4dDo6bmV3KHBvbGljeSwgbG9jYWxfaWQsIGlkZW50aXR5LnRscygmZml4dHVyZS5jYSksIHNlcnZlcik7CisgICAgICAgIGxldCBlcnJvciA9IG1hdGNoIHJlc3VsdCB7CisgICAgICAgICAgICBPayhfKSA9PiBwYW5pYyEoIlRMUyBsb2NhbCBrZXkgYWRtaXNzaW9uIHVzZWQgb25seSB0aGUgaWRlbnRpdHkgaW5kZXgiKSwKKyAgICAgICAgICAgIEVycihlcnJvcikgPT4gZXJyb3IsCisgICAgICAgIH07CisgICAgICAgIGFzc2VydF9lcSEoZXJyb3IudG9fc3RyaW5nKCksICJQUV9UTFNfTE9DQUxfUElOIik7CisgICAgfQorfQorCisjW3Rlc3RdCitmbiBhY3R1YWxfdGxzX3BlZXJfaWRlbnRpdHlfYWxpYXNfcmVmdXNlc19iZWZvcmVfYXBwbGljYXRpb25fZGlzcGF0Y2hfaW5fYm90aF9kaXJlY3Rpb25zKCkgeworICAgIGZvciBjbGllbnRfY2hlY2tzX3NlcnZlciBpbiBbZmFsc2UsIHRydWVdIHsKKyAgICAgICAgbGV0IGZpeHR1cmUgPSBGaXh0dXJlOjpuZXcoKTsKKyAgICAgICAgbGV0IG11dCBzZWxlY3RlZCA9IGZpeHR1cmUucG9saWN5X2Zvcl9zZXJ2ZXJfbmFtZSgibG9jYWxob3N0Iik7CisgICAgICAgIGxldCBzdWJzdGl0dXRlID0gZml4dHVyZS5vdGhlci5zaWduZXIoKTsKKyAgICAgICAgbGV0IHZlcmlmaWVyID0gUHFOYXRpdmVWZXJpZmllcjo6ZnJvbV9waW5uZWRfc3BraSgKKyAgICAgICAgICAgIHN1YnN0aXR1dGUucHVibGljX3Nwa2koKSwKKyAgICAgICAgICAgIHN1YnN0aXR1dGUucHVibGljX2tleV9pZCgpLAorICAgICAgICApCisgICAgICAgIC51bndyYXAoKTsKKyAgICAgICAgLy8gVGhlIHJlYWwgVExTIGV4Y2hhbmdlIGJlbG93IHVzZXMgdmFsaWQgTUwtRFNBIGNlcnRpZmljYXRlcywgbXV0dWFsCisgICAgICAgIC8vIGF1dGhlbnRpY2F0aW9uIGFuZCB0aGUgcGlubmVkIENBLiBUaGlzIHByaXZhdGUgbXV0YXRpb24gc3VwcGxpZXMgdGhlCisgICAgICAgIC8vIGNvbmRpdGlvbmFsIGlkZW50aXR5IGFsaWFzOyBpdCBpcyBub3QgYW4gb2JzZXJ2ZWQgU0hBLTI1NiBjb2xsaXNpb24uCisgICAgICAgIGxldCBvd25lciA9IEFyYzo6Z2V0X211dCgmbXV0IHNlbGVjdGVkKS51bndyYXAoKTsKKyAgICAgICAgaWYgY2xpZW50X2NoZWNrc19zZXJ2ZXIgeworICAgICAgICAgICAgb3duZXIuc2VydmVyID0gdmVyaWZpZXI7CisgICAgICAgIH0gZWxzZSB7CisgICAgICAgICAgICBvd25lci5wZWVycy5pbnNlcnQoZml4dHVyZS5wZWVyLnNpZ25lcigpLnB1YmxpY19rZXlfaWQoKSwgdmVyaWZpZXIpOworICAgICAgICB9CisgICAgICAgIGxldCAoY2xpZW50LCBzZXJ2ZXIpID0gaWYgY2xpZW50X2NoZWNrc19zZXJ2ZXIgeworICAgICAgICAgICAgKAorICAgICAgICAgICAgICAgIFBxVGxzQ2xpZW50OjpuZXcoCisgICAgICAgICAgICAgICAgICAgIHNlbGVjdGVkLAorICAgICAgICAgICAgICAgICAgICBmaXh0dXJlLnBlZXIuc2lnbmVyKCksCisgICAgICAgICAgICAgICAgICAgIGZpeHR1cmUucGVlci50bHMoJmZpeHR1cmUuY2EpLAorICAgICAgICAgICAgICAgICkKKyAgICAgICAgICAgICAgICAudW53cmFwKCksCisgICAgICAgICAgICAgICAgZml4dHVyZS5zZXJ2ZXIoKSwKKyAgICAgICAgICAgICkKKyAgICAgICAgfSBlbHNlIHsKKyAgICAgICAgICAgICgKKyAgICAgICAgICAgICAgICBmaXh0dXJlLmNsaWVudCgpLAorICAgICAgICAgICAgICAgIFBxVGxzU2VydmVyOjpuZXcoCisgICAgICAgICAgICAgICAgICAgIHNlbGVjdGVkLAorICAgICAgICAgICAgICAgICAgICBmaXh0dXJlLnNlcnZlci5zaWduZXIoKSwKKyAgICAgICAgICAgICAgICAgICAgZml4dHVyZS5zZXJ2ZXIudGxzKCZmaXh0dXJlLmNhKSwKKyAgICAgICAgICAgICAgICApCisgICAgICAgICAgICAgICAgLnVud3JhcCgpLAorICAgICAgICAgICAgKQorICAgICAgICB9OworICAgICAgICBsZXQgZGlyZWN0b3J5ID0gdGVtcGZpbGU6OnRlbXBkaXIoKS51bndyYXAoKTsKKyAgICAgICAgbGV0IG5vZGUgPSBOb2RlOjpvcGVuX3dpdGhfcHFfbmV0d29yaygKKyAgICAgICAgICAgIGRpcmVjdG9yeS5wYXRoKCksCisgICAgICAgICAgICBmaXh0dXJlLnNldHRpbmdzLmNsb25lKCksCisgICAgICAgICAgICAxLAorICAgICAgICAgICAgJmZpeHR1cmUucG9saWN5LAorICAgICAgICApCisgICAgICAgIC51bndyYXAoKTsKKyAgICAgICAgbGV0IHByZXBhcmVkID0gY2xpZW50CisgICAgICAgICAgICAucHJlcGFyZSgxLCBjcmF0ZTo6aW5ncmVzczo6bm93KCkudW53cmFwKCkgKyAzMCwgUmVxdWVzdDo6SGVhZCkKKyAgICAgICAgICAgIC51bndyYXAoKTsKKyAgICAgICAgbGV0IGxpc3RlbmVyID0gVGNwTGlzdGVuZXI6OmJpbmQoIjEyNy4wLjAuMTowIikudW53cmFwKCk7CisgICAgICAgIGxpc3RlbmVyLnNldF9ub25ibG9ja2luZyh0cnVlKS51bndyYXAoKTsKKyAgICAgICAgbGV0IGFkZHJlc3MgPSBsaXN0ZW5lci5sb2NhbF9hZGRyKCkudW53cmFwKCk7CisgICAgICAgIGxldCBkZWFkbGluZSA9IEluc3RhbnQ6Om5vdygpICsgRHVyYXRpb246OmZyb21fc2Vjcyg1KTsKKyAgICAgICAgbGV0IHdvcmtlciA9IHRocmVhZDo6c3Bhd24obW92ZSB8fCB7CisgICAgICAgICAgICBsZXQgb3duZXIgPSBNdXRleDo6bmV3KG5vZGUpOworICAgICAgICAgICAgLy8gQSBjbGllbnQgdGhhdCBleHBpcmVzIGJlZm9yZSBjb25uZWN0aW5nIG11c3Qgbm90IGxlYXZlIGpvaW4oKQorICAgICAgICAgICAgLy8gd2FpdGluZyBvbiBhbiB1bmJvdW5kZWQgYWNjZXB0LiBBY2NlcHQgYW5kIGhhbmRzaGFrZSBjb25zdW1lCisgICAgICAgICAgICAvLyB0aGUgc2FtZSBvcmlnaW5hbCBpbnRlcnZhbCwgaW5jbHVkaW5nIGV2ZXJ5IFdvdWxkQmxvY2sgcmV0cnkuCisgICAgICAgICAgICBsZXQgc3RyZWFtID0gKHx8IC0+IFJlc3VsdDxUY3BTdHJlYW0+IHsKKyAgICAgICAgICAgICAgICBsb29wIHsKKyAgICAgICAgICAgICAgICAgICAgY2hlY2tfbGl2ZV9yZXF1ZXN0KGRlYWRsaW5lLCBOb25lKT87CisgICAgICAgICAgICAgICAgICAgIG1hdGNoIGxpc3RlbmVyLmFjY2VwdCgpIHsKKyAgICAgICAgICAgICAgICAgICAgICAgIE9rKChzdHJlYW0sIF8pKSA9PiByZXR1cm4gT2soc3RyZWFtKSwKKyAgICAgICAgICAgICAgICAgICAgICAgIEVycihlcnJvcikgaWYgZXJyb3Iua2luZCgpID09IHN0ZDo6aW86OkVycm9yS2luZDo6V291bGRCbG9jayA9PiB7CisgICAgICAgICAgICAgICAgICAgICAgICAgICAgdGhyZWFkOjpzbGVlcChEdXJhdGlvbjo6ZnJvbV9taWxsaXMoMikpOworICAgICAgICAgICAgICAgICAgICAgICAgfQorICAgICAgICAgICAgICAgICAgICAgICAgRXJyKGVycm9yKSA9PiByZXR1cm4gRXJyKGVycm9yLmludG8oKSksCisgICAgICAgICAgICAgICAgICAgIH0KKyAgICAgICAgICAgICAgICB9CisgICAgICAgICAgICB9KSgpOworICAgICAgICAgICAgbGV0IHJlc3VsdCA9IHN0cmVhbS5hbmRfdGhlbih8c3RyZWFtfCBzZXJ2ZXIuY29ubmVjdGlvbihzdHJlYW0sICZvd25lciwgZGVhZGxpbmUpKTsKKyAgICAgICAgICAgIChyZXN1bHQsIG93bmVyLmludG9faW5uZXIoKS51bndyYXAoKSkKKyAgICAgICAgfSk7CisgICAgICAgIGxldCBjbGllbnRfcmVzdWx0ID0gY2xpZW50LmV4Y2hhbmdlKGFkZHJlc3MsIHByZXBhcmVkLndpcmUoKSwgZGVhZGxpbmUpOworICAgICAgICBsZXQgKHNlcnZlcl9yZXN1bHQsIG5vZGUpID0gd29ya2VyLmpvaW4oKS51bndyYXAoKTsKKyAgICAgICAgbGV0IGVycm9yID0gaWYgY2xpZW50X2NoZWNrc19zZXJ2ZXIgeworICAgICAgICAgICAgY2xpZW50X3Jlc3VsdC5leHBlY3RfZXJyKCJUTFMgY2xpZW50IG11c3QgcmVqZWN0IGFuIGFsaWFzZWQgc2VydmVyIGtleSIpCisgICAgICAgIH0gZWxzZSB7CisgICAgICAgICAgICBzZXJ2ZXJfcmVzdWx0LmV4cGVjdF9lcnIoIlRMUyBzZXJ2ZXIgbXVzdCByZWplY3QgYW4gYWxpYXNlZCBjbGllbnQga2V5IikKKyAgICAgICAgfTsKKyAgICAgICAgYXNzZXJ0X2VxIShlcnJvci50b19zdHJpbmcoKSwgIlBRX1RMU19QRUVSX1BJTiIpOworICAgICAgICBsZXQgc3RhdHVzID0gbm9kZS5wcV9uZXR3b3JrX3N0YXR1cygmZml4dHVyZS5wb2xpY3kpLnVud3JhcCgpOworICAgICAgICBhc3NlcnRfZXEhKHN0YXR1c1sicmVjb3JkcyJdLCAwKTsKKyAgICAgICAgYXNzZXJ0X2VxIShzdGF0dXNbImluYm91bmRfc2lnbmF0dXJlX2F0dGVtcHRzIl0sIDApOworICAgIH0KIH0KIAogI1t0ZXN0XQo='}
ENV = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_NO_LAZY_FETCH="1", CARGO_BUILD_JOBS="2")
STEPS = []
BUFFERED = []
LOGS = None


def sha(data):
    return hashlib.sha256(data).hexdigest()


def step(name, args, cwd=SOURCE, timeout=120, required=True):
    started = time.time()
    process = subprocess.Popen(args, cwd=cwd, env=ENV, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    try:
        out, err = process.communicate(timeout=timeout)
        code = process.returncode
    except subprocess.TimeoutExpired:
        # Only this exact child session and its descendants are signalled.
        os.killpg(process.pid, signal.SIGTERM)
        try:
            out, err = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            out, err = process.communicate()
        code, err = 124, err + b"\nSUBPROCESS_TIMEOUT\n"
    row = {"name": name, "args": args, "cwd": str(cwd), "exit": code,
           "seconds": time.time() - started, "stdout_sha256": sha(out),
           "stderr_sha256": sha(err), "stdout_bytes": len(out), "stderr_bytes": len(err)}
    STEPS.append(row)
    if LOGS:
        (LOGS / (name + ".stdout.log")).write_bytes(out)
        (LOGS / (name + ".stderr.log")).write_bytes(err)
        (LOGS / "steps.json").write_text(json.dumps(STEPS, indent=2) + "\n")
    else:
        BUFFERED.append((name, out, err))
    print(json.dumps(row), flush=True)
    if required and code:
        print(err.decode(errors="replace")[-4000:], flush=True)
        raise RuntimeError("STEP_FAILED:" + name)
    return code, out, err


def verify_originals():
    for name, expected in ORIGINAL_BLOBS.items():
        data = (REPO / name).read_bytes()
        actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if actual != expected:
            raise RuntimeError("ORIGINAL_BLOB_MISMATCH:" + name)


def main():
    global LOGS
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    if not args.execute:
        parser.error("--execute is required on the authorized rog host")
    if sys.platform != "linux" or not SOURCE.is_dir():
        raise RuntimeError("EXPECTED_ROG_SOURCE_NOT_FOUND")
    if BASE.exists():
        raise RuntimeError("EXCLUSIVE_DESTINATION_EXISTS_REVIEW_PRIOR_EVIDENCE")
    _, who, _ = step("github-identity", ["gh", "api", "user", "--jq", ".login"], timeout=45)
    if who.strip() != b"ProfHepta":
        raise RuntimeError("EXPECTED_GITHUB_ADMIN_IDENTITY")
    step("rustup-toolchains", ["rustup", "toolchain", "list"])
    step("rustc-195", ["rustup", "run", "1.95.0", "rustc", "--version"])
    step("cargo-195", ["rustup", "run", "1.95.0", "cargo", "--version"])
    step("source-preflight", ["bash", "scripts/project-preflight.sh"])
    BASE.mkdir(mode=0o700)
    LOGS = BASE / "logs"
    LOGS.mkdir()
    for name, out, err in BUFFERED:
        (LOGS / (name + ".stdout.log")).write_bytes(out)
        (LOGS / (name + ".stderr.log")).write_bytes(err)
    step("isolated-clone", ["git", "clone", "--shared", "--no-checkout", str(SOURCE), str(REPO)], cwd=BASE, timeout=180)
    step("isolated-origin", ["git", "remote", "set-url", "origin", "https://github.com/TrillionniumFoundation/Trillionnium-Chain.git"], cwd=REPO)
    code, _, _ = step("checkout-cached-basis", ["git", "checkout", "--detach", BASIS], cwd=REPO, timeout=90, required=False)
    if code:
        step("fetch-exact-basis", ["git", "-c", "credential.helper=!gh auth git-credential", "fetch", "--refetch", "--no-tags", "--depth=1", "origin", BASIS], cwd=REPO, timeout=300)
        step("checkout-fetched-basis", ["git", "checkout", "--detach", BASIS], cwd=REPO, timeout=120)
    _, head, _ = step("basis-head", ["git", "rev-parse", "HEAD"], cwd=REPO)
    if head.strip().decode() != BASIS:
        raise RuntimeError("BASIS_MISMATCH")
    step("isolated-preflight", ["bash", "scripts/project-preflight.sh"], cwd=REPO)
    verify_originals()
    lock_before = sha((REPO / "trillionnium/Cargo.lock").read_bytes())
    for name, digest in PATCH_HASHES.items():
        data = base64.b64decode(PATCH_DATA[name], validate=True)
        if sha(data) != digest:
            raise RuntimeError("PATCH_DIGEST_MISMATCH:" + name)
        (BASE / name).write_bytes(data)
    # Use the exact repository provider builder and its genuine smoke test.
    # No system 3.5.5 substitution and no edits to the Rust toolchain or lock.
    provider_script = (REPO / "scripts/ci/prepare_pq_provider.sh").read_text()
    if "3.5.9" not in provider_script or "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a" not in provider_script:
        raise RuntimeError("PROVIDER_CONTRACT_MISMATCH")
    runner = BASE / "runner-temp"
    runner.mkdir()
    provider_env = BASE / "provider.env"
    provider_env.touch()
    receipts = BASE / "provider-receipts"
    receipts.mkdir()
    ENV.update(RUNNER_TEMP=str(runner), GITHUB_ENV=str(provider_env), TRNM_CI_RECEIPT_DIR=str(receipts), CARGO_TARGET_DIR=str(BASE / "target"))
    step("provider-build-smoke", ["bash", "scripts/ci/prepare_pq_provider.sh"], cwd=REPO, timeout=1800)
    for line in provider_env.read_text().splitlines():
        if not line:
            continue
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise RuntimeError("INVALID_PROVIDER_ENV_RECORD")
        ENV[key] = value
    if ENV.get("TRNM_PQ_OPENSSL_VERSION") != "3.5.9":
        raise RuntimeError("PROVIDER_VERSION_RECORD_MISMATCH")
    step("provider-version", [ENV["TRNM_PQ_OPENSSL"], "version", "-a"], cwd=REPO)
    step("provider-algorithms", [ENV["TRNM_PQ_OPENSSL"], "list", "-signature-algorithms"], cwd=REPO)
    cargo = ["cargo", "+1.95.0"]
    scope = ["--locked", "--manifest-path", "trillionnium/Cargo.toml", "-p", "trnm-pon-node", "--lib", "--all-features"]
    step("negative-patch-check", ["git", "apply", "--check", str(BASE / "negative-controls-only.patch")], cwd=REPO)
    step("negative-patch-apply", ["git", "apply", str(BASE / "negative-controls-only.patch")], cwd=REPO)
    _, registry, _ = step("negative-test-registry", cargo + ["test"] + scope + ["--", "--list"], cwd=REPO, timeout=1800)
    controls = [
        "ingress::pq_network::canonical_tests::pq_client_requires_complete_key_pin_after_identity_lookup",
        "ingress::pq_network::tls::tests::tls_local_identity_requires_complete_key_pin_for_both_roles",
        "ingress::pq_network::tls::tests::actual_tls_peer_identity_alias_refuses_before_application_dispatch_in_both_directions",
    ]
    for index, control in enumerate(controls):
        if registry.count((control + ": test").encode()) != 1:
            raise RuntimeError("NEGATIVE_TEST_REGISTRY_MISMATCH:" + control)
        code, out, err = step("negative-original-" + str(index + 1), cargo + ["test"] + scope + [control, "--", "--exact", "--show-output", "--test-threads=1"], cwd=REPO, timeout=240, required=False)
        if code != 101 or b"test result: FAILED" not in out or (control + " ... FAILED").encode() not in out:
            raise RuntimeError("NEGATIVE_ORIGINAL_DID_NOT_FAIL_AS_A_TEST:" + control)
    step("negative-patch-reverse", ["git", "apply", "--reverse", str(BASE / "negative-controls-only.patch")], cwd=REPO)
    verify_originals()
    step("fix-preflight", ["bash", "scripts/project-preflight.sh"], cwd=REPO)
    step("fix-patch-check", ["git", "apply", "--check", str(BASE / "exact-spki.patch")], cwd=REPO)
    step("fix-patch-apply", ["git", "apply", str(BASE / "exact-spki.patch")], cwd=REPO)
    step("locked-metadata", cargo + ["metadata", "--locked", "--manifest-path", "trillionnium/Cargo.toml", "--format-version", "1"], cwd=REPO, timeout=240)
    for name, suite in (("canonical-suite", "ingress::pq_network::canonical_tests"), ("tls-suite", "ingress::pq_network::tls::tests")):
        code, out, err = step(name, cargo + ["test"] + scope + [suite, "--", "--show-output", "--test-threads=1"], cwd=REPO, timeout=1800, required=False)
        if code == 0 and (b"running 0 tests" in out or b"test result: ok" not in out):
            raise RuntimeError("EMPTY_OR_UNRECOGNIZED_SUITE:" + name)
    step("strict-clippy", cargo + ["clippy", "--locked", "--manifest-path", "trillionnium/Cargo.toml", "-p", "trnm-pon-node", "--lib", "--tests", "--all-features", "--", "-D", "warnings"], cwd=REPO, timeout=1800, required=False)
    step("workspace-fmt-check", cargo + ["fmt", "--manifest-path", "trillionnium/Cargo.toml", "--all", "--", "--check"], cwd=REPO, timeout=120, required=False)
    step("final-diff-check", ["git", "diff", "--check"], cwd=REPO)
    step("final-diff", ["git", "diff", "--binary"], cwd=REPO)
    lock_after = sha((REPO / "trillionnium/Cargo.lock").read_bytes())
    if lock_before != lock_after:
        raise RuntimeError("LOCKFILE_CHANGED")
    failed = [r["name"] for r in STEPS if r["exit"] and not r["name"].startswith("negative-original-") and r["name"] != "checkout-cached-basis"]
    summary = {"basis": BASIS, "patches": PATCH_HASHES, "lock_sha256": lock_after, "scoped_validation_pass": not failed,
               "failed_stages": failed, "source": str(REPO), "raw_logs": str(LOGS), "qualification": "HOLD_NO_GO",
               "limits": "Scoped engineering controls only. A conditional private policy alias is not a constructed SHA-256 collision; no full-chain proof or production qualification."}
    (BASE / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary), flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        failure = {"state": "FAILED", "error_type": type(exc).__name__, "error": str(exc), "steps": STEPS, "qualification": "HOLD_NO_GO"}
        if BASE.is_dir() and LOGS is not None:
            (BASE / "failure.json").write_text(json.dumps(failure, indent=2) + "\n")
        print(json.dumps(failure), flush=True)
        sys.exit(1)
