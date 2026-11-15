#!/usr/bin/env python3
"""One reviewed test-phase correction; retain the failed run and exact native test."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import time

ROOT = Path('/home/qian-qi/work/chain-pq-authority-20261108-9d315')
REPO = ROOT / 'repo'
OUT = ROOT / 'validation/node-expiry-fixture-fix-01'
PRIOR = ROOT / 'validation/integrated-source-01'
PARENT = 'af6b06fa1cb944e639148b58e9765fe2bb0065ab'
BRANCH = 'fix/chain-pq-authority-preflight-20261108-9d315'
EV = 'evidence/pq-authority-preflight-20261108-9d315'
RUNNER = REPO / EV / 'authority-integrated-validation-runner.py'
RUNNER_SHA = 'f5fc66625c09cfccf5054ec705a49c2a88f234c0620e6e6426aa4b7efcb71b86'
TEST_PATH = 'trillionnium/crates/trnm-pon-node/src/release_owner/service_tests.rs'
REPORT_PATH = 'docs/security/PQ_AUTHORITY_PREFLIGHT_20261108.md'
CORPUS_PATH = 'config/pon/pq-cross-branch-corpus-v1.json'
CHANGED = sorted([TEST_PATH, REPORT_PATH, CORPUS_PATH])
TEST_NAME = ('release_owner::service_tests::'
             'admitted_completion_after_expiry_lost_reply_is_exact_and_cold_does_not_redispatch')
BEFORE_SHA = '1b47a8384fa20bfd7c2a15c41f4a693eb8cede29c8100f45885d8ac80e66fee0'
PROPOSAL_SHA = '8f12bea3c6c3fc505c18d43844a7d86f6471988ba89bab1e61a9ea7457fa5f82'
REPORT_SHA = 'a92a1613e4da719447ab20587a35f08ea81827af7d01ef05a53a80b7d9b650e4'
PRIOR_SUMMARY_SHA = 'f914399f9b6ea68ef81e56fc3ff53b4164ddf59df2dcbbf8b0f984f7009ade39'
PROPOSAL_B64 = 'Ly8hIFJlYWwgc2lnbmVkIENsb2NrIFVEUyArIFNlcnZpY2U6OmFuc3dlciArIGR1cmFibGUgZmlsZXMuIFRoaXMgc3VpdGUgZG9lcyBub3QKLy8hIHJ1biB0aGUgZnJvbnRpZXIgbGlzdGVuZXIncyBjcm9zcy1VSUQgcGVlciBwYXRoIG9yIHByb3ZlIC9ldGMgcHJvdmlzaW9uaW5nLgp1c2Ugc3VwZXI6OmZyb250aWVyOjp7RnJvbnRpZXIsIFZhbGlkaXR5fTsKdXNlIHN1cGVyOjpmcm9udGllcl9zZXJ2aWNlOjpTZXJ2aWNlOwp1c2Ugc3VwZXI6OnNlcnZpY2VfZmF1bHRzOjp7c2VsZiBhcyBmYXVsdHMsIFBvaW50fTsKdXNlIHN1cGVyOjpzZXJ2aWNlX3Rlc3RfZml4dHVyZTo6e3dyaXRlLCBGaXh0dXJlLCBUaW1lLCBOQU1FU1BBQ0V9Owp1c2Ugc3VwZXI6OnRydXN0X3dpcmUgYXMgd2lyZTsKdXNlIHN0ZDo6c3luYzo6YXRvbWljOjp7QXRvbWljQm9vbCwgT3JkZXJpbmd9Owp1c2Ugc3RkOjpzeW5jOjpBcmM7CnVzZSBzdGQ6OnRpbWU6OntEdXJhdGlvbiwgSW5zdGFudH07CgpmbiBkZWFkbGluZSgpIC0+IEluc3RhbnQgewogICAgSW5zdGFudDo6bm93KCkgKyBEdXJhdGlvbjo6ZnJvbV9zZWNzKDIpCn0KZm4gcHJvcG9zYWwoKSAtPiBGcm9udGllciB7CiAgICBGcm9udGllcjo6c3VjY2Vzc29yKE5BTUVTUEFDRSwgTm9uZSwgYiJhY3R1YWwtaW5kZXgiKS51bndyYXAoKQp9CmZuIHdpbmRvdyhmOiAmRml4dHVyZSwgc2Vjb25kczogdTY0KSAtPiBWYWxpZGl0eSB7CiAgICBWYWxpZGl0eSB7CiAgICAgICAgbm90X2JlZm9yZTogMCwKICAgICAgICBleHBpcmVzX2F0OiBmLnRpbWUubm93KCkgKyBzZWNvbmRzLAogICAgfQp9CmZuIHdhaXRfdW50aWwodGltZTogJlRpbWUsIHNlY29uZHM6IHU2NCkgewogICAgbGV0IHVudGlsID0gSW5zdGFudDo6bm93KCkgKyBEdXJhdGlvbjo6ZnJvbV9zZWNzKDIwKTsKICAgIHdoaWxlIHRpbWUubm93KCkgPCBzZWNvbmRzIHsKICAgICAgICBhc3NlcnQhKAogICAgICAgICAgICBJbnN0YW50Ojpub3coKSA8IHVudGlsLAogICAgICAgICAgICAicmVhbCBmaXh0dXJlIGNsb2NrIGRpZCBub3QgcmVhY2ggdGFyZ2V0IgogICAgICAgICk7CiAgICAgICAgc3RkOjp0aHJlYWQ6OnNsZWVwKER1cmF0aW9uOjpmcm9tX21pbGxpcygxMCkpOwogICAgfQp9CmZuIHJvd19mcm9udGllcihmOiAmRml4dHVyZSkgLT4gT3B0aW9uPEZyb250aWVyPiB7CiAgICBsZXQgcm93OiBzZXJkZV9qc29uOjpWYWx1ZSA9IHNlcmRlX2pzb246OmZyb21fc2xpY2UoJmYucm93KCkpLnVud3JhcCgpOwogICAgc2VyZGVfanNvbjo6ZnJvbV92YWx1ZShyb3dbImZyb250aWVyIl0uY2xvbmUoKSkudW53cmFwKCkKfQpmbiByb3dfZmxvb3IoZjogJkZpeHR1cmUpIC0+IHU2NCB7CiAgICBzZXJkZV9qc29uOjpmcm9tX3NsaWNlOjo8c2VyZGVfanNvbjo6VmFsdWU+KCZmLnJvdygpKS51bndyYXAoKVsidGltZV9mbG9vciJdCiAgICAgICAgLmFzX3U2NCgpCiAgICAgICAgLnVud3JhcCgpCn0KCiNbdGVzdF0KZm4gc2lnbmVkX2Nhc191c2VzX2V4YWN0X29sZF9vbmNlX2FuZF9yZXR1cm5zX29ubHlfdGhlX29ic2VydmVkX2xvd2VyX2Zsb29yKCkgewogICAgbGV0IG11dCBmID0gRml4dHVyZTo6bmV3KCk7CiAgICBsZXQgbXV0IHNlcnZpY2UgPSBmLmluaXRpYWxpemVkKCk7CiAgICBmLnNjb3BlKHx8IHsKICAgICAgICBsZXQgbmV4dCA9IHByb3Bvc2FsKCk7CiAgICAgICAgbGV0IHJhdyA9IGYucmVxdWVzdChOb25lLCBTb21lKG5leHQuY2xvbmUoKSksIFNvbWUod2luZG93KCZmLCAzMCkpKTsKICAgICAgICBsZXQgYW5zd2VyID0gc2VydmljZS5hbnN3ZXIoJnJhdywgZGVhZGxpbmUoKSkudW53cmFwKCk7CiAgICAgICAgbGV0IHJlcGx5ID0gZi5yZXBseSgmcmF3LCAmYW5zd2VyKTsKICAgICAgICBhc3NlcnQhKHJlcGx5LmFjY2VwdGVkKTsKICAgICAgICBhc3NlcnRfZXEhKHJlcGx5Lm9wZXJhdGlvbiwgd2lyZTo6T3BlcmF0aW9uOjpDb21wYXJlQW5kU2V0KTsKICAgICAgICBhc3NlcnRfZXEhKHJlcGx5LmZyb250aWVyLCBTb21lKG5leHQuY2xvbmUoKSkpOwogICAgICAgIGFzc2VydF9lcSEocm93X2Zsb29yKCZmKSwgcmVwbHkubm93X3NlY29uZHMpOwogICAgICAgIGFzc2VydF9lcSEocmVwbHkubm93X3NlY29uZHMsIGYudGltZS5sYXN0X3NpZ25lZCgpKTsKICAgICAgICBhc3NlcnQhKHJlcGx5Lm5vd19zZWNvbmRzIDw9IGYudGltZS5ub3coKSk7CiAgICAgICAgYXNzZXJ0X2VxIShmYXVsdHM6OmFkbWlzc2lvbnMoKSwgMSk7CiAgICAgICAgbGV0IHJlcGxheSA9IGYucmVwbHkoJnJhdywgJnNlcnZpY2UuYW5zd2VyKCZyYXcsIGRlYWRsaW5lKCkpLnVud3JhcCgpKTsKICAgICAgICBhc3NlcnQhKCFyZXBsYXkuYWNjZXB0ZWQpOwogICAgICAgIGFzc2VydF9lcSEocmVwbGF5LmZyb250aWVyLCBTb21lKG5leHQpKTsKICAgICAgICBhc3NlcnRfZXEhKHJvd19mbG9vcigmZiksIHJlcGxheS5ub3dfc2Vjb25kcyk7CiAgICAgICAgYXNzZXJ0X2VxIShyZXBsYXkubm93X3NlY29uZHMsIGYudGltZS5sYXN0X3NpZ25lZCgpKTsKICAgICAgICBhc3NlcnRfZXEhKGZhdWx0czo6YWRtaXNzaW9ucygpLCAxKTsKICAgIH0pOwp9CgpmbiBwYXVzZV9iZWZvcmVfYWRtaXNzaW9uKHBvaW50OiBQb2ludCkgewogICAgbGV0IG11dCBmID0gRml4dHVyZTo6bmV3KCk7CiAgICBsZXQgbXV0IHNlcnZpY2UgPSBmLmluaXRpYWxpemVkKCk7CiAgICBsZXQgdmFsaWRpdHkgPSB3aW5kb3coJmYsIDIpOwogICAgbGV0IHJhdyA9IGYucmVxdWVzdChOb25lLCBTb21lKHByb3Bvc2FsKCkpLCBTb21lKHZhbGlkaXR5KSk7CiAgICBsZXQgb3JpZ2luYWwgPSBmLnJvdygpOwogICAgbGV0IHJlYWNoZWQgPSBBcmM6Om5ldyhBdG9taWNCb29sOjpuZXcoZmFsc2UpKTsKICAgIGxldCBtYXJrZXIgPSByZWFjaGVkLmNsb25lKCk7CiAgICBsZXQgdGltZSA9IGYudGltZS5jbG9uZSgpOwogICAgZi5zY29wZSh8fCB7CiAgICAgICAgZmF1bHRzOjpvbmNlKHBvaW50LCBtb3ZlIHx8IHsKICAgICAgICAgICAgbWFya2VyLnN0b3JlKHRydWUsIE9yZGVyaW5nOjpTZXFDc3QpOwogICAgICAgICAgICBzdGQ6OnRocmVhZDo6c2xlZXAoRHVyYXRpb246OmZyb21fbWlsbGlzKDExMDApKTsKICAgICAgICAgICAgYXNzZXJ0ISh0aW1lLm5vdygpID49IHZhbGlkaXR5LmV4cGlyZXNfYXQpOwogICAgICAgICAgICBPaygoKSkKICAgICAgICB9KTsKICAgICAgICBsZXQgZXJyb3IgPSBzZXJ2aWNlLmFuc3dlcigmcmF3LCBkZWFkbGluZSgpKS51bndyYXBfZXJyKCk7CiAgICAgICAgYXNzZXJ0IShyZWFjaGVkLmxvYWQoT3JkZXJpbmc6OlNlcUNzdCkpOwogICAgICAgIGFzc2VydF9lcSEoZXJyb3Iua2luZCgpLCBzdGQ6OmlvOjpFcnJvcktpbmQ6OlBlcm1pc3Npb25EZW5pZWQpOwogICAgICAgIGFzc2VydF9lcSEoCiAgICAgICAgICAgIGVycm9yLnRvX3N0cmluZygpLAogICAgICAgICAgICAiTTE1IGNvbnNlcnZhdGl2ZSB0cnVzdGVkIHRpbWUgaW50ZXJ2YWwgaXMgb3V0c2lkZSB0aGUgZXhhY3Qgd2luZG93IgogICAgICAgICk7CiAgICAgICAgYXNzZXJ0X2VxIShmYXVsdHM6OmFkbWlzc2lvbnMoKSwgMCk7CiAgICAgICAgYXNzZXJ0X2VxIShmLnJvdygpLCBvcmlnaW5hbCk7CiAgICAgICAgYXNzZXJ0X2VxIShyb3dfZnJvbnRpZXIoJmYpLCBOb25lKTsKICAgICAgICBhc3NlcnRfZXEhKAogICAgICAgICAgICBzZXJ2aWNlLmFuc3dlcigmcmF3LCBkZWFkbGluZSgpKS51bndyYXBfZXJyKCkudG9fc3RyaW5nKCksCiAgICAgICAgICAgICJNMTUgc2VydmljZSBpcyBmZW5jZWQiCiAgICAgICAgKTsKICAgIH0pOwp9CgojW3Rlc3RdCmZuIGNsb2NrX3JlcGx5X3RoZW5fcmVhbF9lbGFwc2VkX2V4cGlyeV9yZWZ1c2VzX3dpdGhvdXRfY2FzKCkgewogICAgcGF1c2VfYmVmb3JlX2FkbWlzc2lvbihQb2ludDo6Q2xvY2spOwp9CgojW3Rlc3RdCmZuIGR1cmFibGVfcHJlcGFyYXRpb25fdGhlbl9yZWFsX2VsYXBzZWRfZXhwaXJ5X3JlZnVzZXNfd2l0aG91dF9jYXMoKSB7CiAgICBwYXVzZV9iZWZvcmVfYWRtaXNzaW9uKFBvaW50OjpQcmVwYXJlZCk7Cn0KCiNbdGVzdF0KZm4gYWRtaXR0ZWRfY29tcGxldGlvbl9hZnRlcl9leHBpcnlfbG9zdF9yZXBseV9pc19leGFjdF9hbmRfY29sZF9kb2VzX25vdF9yZWRpc3BhdGNoKCkgewogICAgbGV0IG11dCBmID0gRml4dHVyZTo6bmV3KCk7CiAgICBsZXQgbXV0IHNlcnZpY2UgPSBmLmluaXRpYWxpemVkKCk7CiAgICBsZXQgbmV4dCA9IHByb3Bvc2FsKCk7CiAgICAvLyBLZWVwIHNldHVwIHRpbWUgc2VwYXJhdGUgZnJvbSB0aGUgcG9zdC1hZG1pc3Npb24gZXhwaXJ5IGJlaW5nIGV4ZXJjaXNlZC4KICAgIC8vIFRoZSByZWFsIGZpeHR1cmUgY2xvY2sgc3RpbGwgYWR2YW5jZXMgYXQgdGhlIGRlY2xhcmVkIG1heGltdW0gMnggcmF0ZS4KICAgIGxldCBjcmVhdGVkX2F0ID0gZi50aW1lLm5vdygpOwogICAgbGV0IHNob3J0X3dpbmRvd19lbmQgPSBjcmVhdGVkX2F0ICsgMjsKICAgIGxldCB2YWxpZGl0eSA9IFZhbGlkaXR5IHsKICAgICAgICBub3RfYmVmb3JlOiAwLAogICAgICAgIGV4cGlyZXNfYXQ6IGNyZWF0ZWRfYXQgKyAzMCwKICAgIH07CiAgICBsZXQgcmF3ID0gZi5yZXF1ZXN0KE5vbmUsIFNvbWUobmV4dC5jbG9uZSgpKSwgU29tZSh2YWxpZGl0eSkpOwogICAgbGV0IHRpbWUgPSBmLnRpbWUuY2xvbmUoKTsKICAgIGYuc2NvcGUofHwgewogICAgICAgIC8vIFJlcHJvZHVjZSBhIHByZS1zZW5kIGRlbGF5IHRoYXQgZXhoYXVzdGVkIHRoZSBmb3JtZXIgc2hvcnQgd2luZG93LgogICAgICAgIC8vIFRoZSBzZXJ2aWNlJ3Mgb3JpZ2luYWwgdHdvLXNlY29uZCByZXF1ZXN0IGRlYWRsaW5lIGJlZ2lucyBiZWxvdy4KICAgICAgICB3YWl0X3VudGlsKCZmLnRpbWUsIHNob3J0X3dpbmRvd19lbmQpOwogICAgICAgIGFzc2VydCEoZi50aW1lLm5vdygpID49IHNob3J0X3dpbmRvd19lbmQpOwogICAgICAgIGFzc2VydCEoZi50aW1lLm5vdygpIDwgdmFsaWRpdHkuZXhwaXJlc19hdCk7CiAgICAgICAgZmF1bHRzOjpvbmNlKFBvaW50OjpBZG1pdHRlZCwgbW92ZSB8fCB7CiAgICAgICAgICAgIC8vIFRoaXMgaXMgZGVsaWJlcmF0ZWx5IGFmdGVyIHRoZSByZWFsIGludGVydmFsIGNoZWNrL2RlY2lzaW9uLgogICAgICAgICAgICBhc3NlcnRfZXEhKGZhdWx0czo6YWRtaXNzaW9ucygpLCAxKTsKICAgICAgICAgICAgYXNzZXJ0ISh0aW1lLm5vdygpIDwgdmFsaWRpdHkuZXhwaXJlc19hdCk7CiAgICAgICAgICAgIHdhaXRfdW50aWwoJnRpbWUsIHZhbGlkaXR5LmV4cGlyZXNfYXQpOwogICAgICAgICAgICBhc3NlcnQhKHRpbWUubm93KCkgPj0gdmFsaWRpdHkuZXhwaXJlc19hdCk7CiAgICAgICAgICAgIGZhdWx0czo6b25jZShQb2ludDo6UHVibGlzaGVkLCB8fCB7CiAgICAgICAgICAgICAgICBFcnIoc3RkOjppbzo6RXJyb3I6Om90aGVyKCJsb3N0IGFmdGVyIGR1cmFibGUgY29tcGxldGlvbiIpKQogICAgICAgICAgICB9KTsKICAgICAgICAgICAgT2soKCkpCiAgICAgICAgfSk7CiAgICAgICAgYXNzZXJ0X2VxISgKICAgICAgICAgICAgc2VydmljZS5hbnN3ZXIoJnJhdywgZGVhZGxpbmUoKSkudW53cmFwX2VycigpLnRvX3N0cmluZygpLAogICAgICAgICAgICAibG9zdCBhZnRlciBkdXJhYmxlIGNvbXBsZXRpb24iCiAgICAgICAgKTsKICAgICAgICBhc3NlcnRfZXEhKGZhdWx0czo6YWRtaXNzaW9ucygpLCAxKTsKICAgICAgICBhc3NlcnRfZXEhKHJvd19mcm9udGllcigmZiksIFNvbWUobmV4dC5jbG9uZSgpKSk7CiAgICAgICAgYXNzZXJ0IShyb3dfZmxvb3IoJmYpIDwgdmFsaWRpdHkuZXhwaXJlc19hdCk7CiAgICAgICAgYXNzZXJ0X2VxIShyb3dfZmxvb3IoJmYpLCBmLnRpbWUubGFzdF9zaWduZWQoKSk7CiAgICAgICAgYXNzZXJ0X2VxISgKICAgICAgICAgICAgc2VydmljZS5hbnN3ZXIoJnJhdywgZGVhZGxpbmUoKSkudW53cmFwX2VycigpLnRvX3N0cmluZygpLAogICAgICAgICAgICAiTTE1IHNlcnZpY2UgaXMgZmVuY2VkIgogICAgICAgICk7CiAgICAgICAgZHJvcChzZXJ2aWNlKTsKICAgICAgICBhc3NlcnQhKFNlcnZpY2U6Om9wZW4oZmFsc2UpLmlzX2VycigpKTsgLy8gSW5kZXBlbmRlbnQgb2xkIGhlYWQvZmxvb3IgY2Fubm90IGFkb3B0IHRoZSBEQi4KICAgIH0pOwogICAgZi5waW5fcmV0YWluZWRfcm93KCk7IC8vIE9ubHkgYW4gZXF1YWxpdHkgZml4dHVyZSwgbm90IGluZGVwZW5kZW50IGN1c3RvZHkgZXZpZGVuY2UuCiAgICBmLnNjb3BlKHx8IHsKICAgICAgICBsZXQgbXV0IGNvbGQgPSBTZXJ2aWNlOjpvcGVuKGZhbHNlKS51bndyYXAoKTsKICAgICAgICBsZXQgcmV0YWluZWQgPSBmLnJvdygpOwogICAgICAgIGFzc2VydF9lcSEoCiAgICAgICAgICAgIGNvbGQuaW5pdGlhbGl6YXRpb24oKS51bndyYXAoKVsiZnJvbnRpZXIiXSwKICAgICAgICAgICAgc2VyZGVfanNvbjo6dG9fdmFsdWUoJm5leHQpLnVud3JhcCgpCiAgICAgICAgKTsKICAgICAgICBsZXQgZXJyb3IgPSBjb2xkLmFuc3dlcigmcmF3LCBkZWFkbGluZSgpKS51bndyYXBfZXJyKCk7CiAgICAgICAgYXNzZXJ0X2VxIShlcnJvci5raW5kKCksIHN0ZDo6aW86OkVycm9yS2luZDo6UGVybWlzc2lvbkRlbmllZCk7CiAgICAgICAgYXNzZXJ0X2VxIShmYXVsdHM6OmFkbWlzc2lvbnMoKSwgMCk7CiAgICAgICAgYXNzZXJ0X2VxIShmLnJvdygpLCByZXRhaW5lZCk7CiAgICB9KTsKfQoKI1t0ZXN0XQpmbiBwcmVwYXJlZF9mYWlsdXJlX2tlZXBzX2Nhbm9uaWNhbF9yb3dfYW5kX3RlbXBfaXNfbm90X2FkbWlzc2lvbigpIHsKICAgIGxldCBtdXQgZiA9IEZpeHR1cmU6Om5ldygpOwogICAgbGV0IG11dCBzZXJ2aWNlID0gZi5pbml0aWFsaXplZCgpOwogICAgbGV0IHJhdyA9IGYucmVxdWVzdChOb25lLCBTb21lKHByb3Bvc2FsKCkpLCBTb21lKHdpbmRvdygmZiwgMzApKSk7CiAgICBmLnNjb3BlKHx8IHsKICAgICAgICBsZXQgb3JpZ2luYWwgPSBmLnJvdygpOwogICAgICAgIGZhdWx0czo6b25jZShQb2ludDo6UHJlcGFyZWQsIHx8IHsKICAgICAgICAgICAgRXJyKHN0ZDo6aW86OkVycm9yOjpvdGhlcigicHJlcGFyZWQgYmVmb3JlIGRlY2lzaW9uIikpCiAgICAgICAgfSk7CiAgICAgICAgYXNzZXJ0X2VxISgKICAgICAgICAgICAgc2VydmljZS5hbnN3ZXIoJnJhdywgZGVhZGxpbmUoKSkudW53cmFwX2VycigpLnRvX3N0cmluZygpLAogICAgICAgICAgICAicHJlcGFyZWQgYmVmb3JlIGRlY2lzaW9uIgogICAgICAgICk7CiAgICAgICAgYXNzZXJ0X2VxIShmYXVsdHM6OmFkbWlzc2lvbnMoKSwgMCk7CiAgICAgICAgYXNzZXJ0X2VxIShmLnJvdygpLCBvcmlnaW5hbCk7CiAgICAgICAgbGV0IHByZXBhcmVkOiBWZWM8Xz4gPSBzdGQ6OmZzOjpyZWFkX2RpcigmZi5jb25maWd1cmF0aW9uLmRpcmVjdG9yeSkKICAgICAgICAgICAgLnVud3JhcCgpCiAgICAgICAgICAgIC5tYXAofGV8IGUudW53cmFwKCkucGF0aCgpKQogICAgICAgICAgICAuZmlsdGVyKHxwfCB7CiAgICAgICAgICAgICAgICBwLmZpbGVfbmFtZSgpCiAgICAgICAgICAgICAgICAgICAgLnVud3JhcCgpCiAgICAgICAgICAgICAgICAgICAgLnRvX3N0cmluZ19sb3NzeSgpCiAgICAgICAgICAgICAgICAgICAgLmNvbnRhaW5zKCIucHJlcGFyZWQtIikKICAgICAgICAgICAgfSkKICAgICAgICAgICAgLmNvbGxlY3QoKTsKICAgICAgICBhc3NlcnRfZXEhKHByZXBhcmVkLmxlbigpLCAxKTsKICAgICAgICBsZXQgcmF3OiBzZXJkZV9qc29uOjpWYWx1ZSA9CiAgICAgICAgICAgIHNlcmRlX2pzb246OmZyb21fc2xpY2UoJnN0ZDo6ZnM6OnJlYWQoJnByZXBhcmVkWzBdKS51bndyYXAoKSkudW53cmFwKCk7CiAgICAgICAgYXNzZXJ0X2VxIShyYXdbImZyb250aWVyIl0sIHNlcmRlX2pzb246OnRvX3ZhbHVlKHByb3Bvc2FsKCkpLnVud3JhcCgpKTsKICAgICAgICBkcm9wKHNlcnZpY2UpOwogICAgICAgIGxldCBjb2xkID0gU2VydmljZTo6b3BlbihmYWxzZSkudW53cmFwKCk7CiAgICAgICAgYXNzZXJ0IShjb2xkLmluaXRpYWxpemF0aW9uKCkudW53cmFwKClbImZyb250aWVyIl0uaXNfbnVsbCgpKTsKICAgICAgICBhc3NlcnRfZXEhKGZhdWx0czo6YWRtaXNzaW9ucygpLCAwKTsKICAgICAgICBhc3NlcnRfZXEhKGYucm93KCksIG9yaWdpbmFsKTsKICAgIH0pOwp9CgojW3Rlc3RdCmZuIHdyb25nX3NpZ25hdHVyZV9kb21haW5fYmluZGluZ19uYW1lc3BhY2VfYW5kX25vbmNlX2Nhbm5vdF9tdXRhdGVfb3JfZmVuY2UoKSB7CiAgICBsZXQgbXV0IGYgPSBGaXh0dXJlOjpuZXcoKTsKICAgIGxldCBtdXQgc2VydmljZSA9IGYuaW5pdGlhbGl6ZWQoKTsKICAgIGxldCB2YWxpZCA9IGYucmVxdWVzdChOb25lLCBTb21lKHByb3Bvc2FsKCkpLCBTb21lKHdpbmRvdygmZiwgMzApKSk7CiAgICBsZXQgd3Jvbmdfa2V5ID0gc3VwZXI6OnByb29mX3Rlc3Rfa2V5czo6a2V5KDkzKTsKICAgIGYuc2NvcGUofHwgewogICAgICAgIGxldCBvcmlnaW5hbCA9IGYucm93KCk7CiAgICAgICAgZm9yIGZhdWx0IGluIDAuLjcgewogICAgICAgICAgICBsZXQgbXV0IHNpZ25lZDogd2lyZTo6U2lnbmVkPHdpcmU6OlJlcXVlc3Q+ID0gd2lyZTo6ZGVjb2RlKCZ2YWxpZCkudW53cmFwKCk7CiAgICAgICAgICAgIGxldCBiYWQgPSBtYXRjaCBmYXVsdCB7CiAgICAgICAgICAgICAgICAwID0+IHsKICAgICAgICAgICAgICAgICAgICBzaWduZWQuYm9keS5iaW5kaW5nWzBdIF49IDE7CiAgICAgICAgICAgICAgICAgICAgd2lyZTo6c2lnbih3aXJlOjpSRVFVRVNULCBzaWduZWQuYm9keSwgJmYub3duZXJfa2V5KS51bndyYXAoKQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgMSA9PiB7CiAgICAgICAgICAgICAgICAgICAgc2lnbmVkLmJvZHkubmFtZXNwYWNlWzBdIF49IDE7CiAgICAgICAgICAgICAgICAgICAgd2lyZTo6c2lnbih3aXJlOjpSRVFVRVNULCBzaWduZWQuYm9keSwgJmYub3duZXJfa2V5KS51bndyYXAoKQogICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgMiA9PiB7CiAgICAgICAgICAgICAgICAgICAgc2lnbmVkLmJvZHkuY2hhbGxlbmdlID0gWzA7IDMyXTsKICAgICAgICAgICAgICAgICAgICB3aXJlOjpzaWduKHdpcmU6OlJFUVVFU1QsIHNpZ25lZC5ib2R5LCAmZi5vd25lcl9rZXkpLnVud3JhcCgpCiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICAzID0+IHsKICAgICAgICAgICAgICAgICAgICBzaWduZWQuYm9keS5vcGVyYXRpb24gPSB3aXJlOjpPcGVyYXRpb246OkNsb2NrOwogICAgICAgICAgICAgICAgICAgIHdpcmU6OnNpZ24od2lyZTo6UkVRVUVTVCwgc2lnbmVkLmJvZHksICZmLm93bmVyX2tleSkudW53cmFwKCkKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgIDQgPT4gd2lyZTo6c2lnbih3aXJlOjpSRVFVRVNULCBzaWduZWQuYm9keSwgJndyb25nX2tleSkudW53cmFwKCksCiAgICAgICAgICAgICAgICA1ID0+IHsKICAgICAgICAgICAgICAgICAgICBzaWduZWQuc2lnbmF0dXJlWzBdIF49IDE7CiAgICAgICAgICAgICAgICAgICAgd2lyZTo6Y2Fub25pY2FsKCZzaWduZWQpLnVud3JhcCgpCiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBfID0+IHdpcmU6OnNpZ24od2lyZTo6Q0xPQ0tfUkVQTFksIHNpZ25lZC5ib2R5LCAmZi5vd25lcl9rZXkpLnVud3JhcCgpLAogICAgICAgICAgICB9OwogICAgICAgICAgICBhc3NlcnQhKHNlcnZpY2UuYW5zd2VyKCZiYWQsIGRlYWRsaW5lKCkpLmlzX2VycigpKTsKICAgICAgICAgICAgYXNzZXJ0X2VxIShmLnJvdygpLCBvcmlnaW5hbCk7CiAgICAgICAgICAgIGFzc2VydF9lcSEoZmF1bHRzOjphZG1pc3Npb25zKCksIDApOwogICAgICAgIH0KICAgICAgICBsZXQgbG9hZCA9IGYucmVxdWVzdChOb25lLCBOb25lLCBOb25lKTsKICAgICAgICBsZXQgcmVwbHkgPSBmLnJlcGx5KCZsb2FkLCAmc2VydmljZS5hbnN3ZXIoJmxvYWQsIGRlYWRsaW5lKCkpLnVud3JhcCgpKTsKICAgICAgICBhc3NlcnQhKHJlcGx5LmFjY2VwdGVkICYmIHJlcGx5LmZyb250aWVyLmlzX25vbmUoKSk7CiAgICAgICAgYXNzZXJ0X2VxIShmYXVsdHM6OmFkbWlzc2lvbnMoKSwgMCk7CiAgICB9KTsKfQoKI1t0ZXN0XQpmbiBhY3R1YWxfc2lnbmVkX2Nsb2NrX3dyb25nX3JlcXVlc3Rfbm9uY2VfbmFtZXNwYWNlX29yX2JhY2t3YXJkX2Zsb29yX2ZlbmNlcygpIHsKICAgIGZvciBmYXVsdCBpbiAxLi49NCB7CiAgICAgICAgbGV0IG11dCBmID0gRml4dHVyZTo6bmV3KCk7CiAgICAgICAgbGV0IG11dCBzZXJ2aWNlID0gZi5pbml0aWFsaXplZCgpOwogICAgICAgIGxldCByYXcgPSBmLnJlcXVlc3QoTm9uZSwgU29tZShwcm9wb3NhbCgpKSwgU29tZSh3aW5kb3coJmYsIDMwKSkpOwogICAgICAgIGYudGltZS5tb2RlLnN0b3JlKGZhdWx0LCBPcmRlcmluZzo6U2VxQ3N0KTsKICAgICAgICBmLnNjb3BlKHx8IHsKICAgICAgICAgICAgbGV0IG9yaWdpbmFsID0gZi5yb3coKTsKICAgICAgICAgICAgYXNzZXJ0X2VxISgKICAgICAgICAgICAgICAgIHNlcnZpY2UuYW5zd2VyKCZyYXcsIGRlYWRsaW5lKCkpLnVud3JhcF9lcnIoKS50b19zdHJpbmcoKSwKICAgICAgICAgICAgICAgICJNMTUgaW5kZXBlbmRlbnQgc2lnbmVkIGNsb2NrIGJpbmRpbmcvZmxvb3IiCiAgICAgICAgICAgICk7CiAgICAgICAgICAgIGFzc2VydF9lcSEoZi5yb3coKSwgb3JpZ2luYWwpOwogICAgICAgICAgICBhc3NlcnRfZXEhKGZhdWx0czo6YWRtaXNzaW9ucygpLCAwKTsKICAgICAgICAgICAgZi50aW1lLm1vZGUuc3RvcmUoMCwgT3JkZXJpbmc6OlNlcUNzdCk7CiAgICAgICAgICAgIGFzc2VydF9lcSEoCiAgICAgICAgICAgICAgICBzZXJ2aWNlLmFuc3dlcigmcmF3LCBkZWFkbGluZSgpKS51bndyYXBfZXJyKCkudG9fc3RyaW5nKCksCiAgICAgICAgICAgICAgICAiTTE1IHNlcnZpY2UgaXMgZmVuY2VkIgogICAgICAgICAgICApOwogICAgICAgIH0pOwogICAgfQp9CgojW3Rlc3RdCmZuIGxhc3RfY2xvY2tfY2FsbGJhY2tfbG9ja19yb3dfb3JfcHJvdmlzaW9uaW5nX2RyaWZ0X3JlZnVzZXNfYW5kX3JldGFpbnNfZmF1bHQoKSB7CiAgICBmb3IgZmF1bHQgaW4gMC4uMyB7CiAgICAgICAgbGV0IG11dCBmID0gRml4dHVyZTo6bmV3KCk7CiAgICAgICAgbGV0IG11dCBzZXJ2aWNlID0gZi5pbml0aWFsaXplZCgpOwogICAgICAgIGxldCByYXcgPSBmLnJlcXVlc3QoTm9uZSwgU29tZShwcm9wb3NhbCgpKSwgU29tZSh3aW5kb3coJmYsIDMwKSkpOwogICAgICAgIGxldCBvcmlnaW5hbCA9IGYucm93KCk7CiAgICAgICAgbGV0IHJvb3QgPSBmLnJvb3RfZmlsZS5jbG9uZSgpOwogICAgICAgIGxldCBkaXJlY3RvcnkgPSBmLmNvbmZpZ3VyYXRpb24uZGlyZWN0b3J5LmNsb25lKCk7CiAgICAgICAgbGV0IG11dCBjaGFuZ2VkID0gZi5jb25maWd1cmF0aW9uLmNsb25lKCk7CiAgICAgICAgY2hhbmdlZC5jbG9jay5iaW5kaW5nWzBdIF49IDE7CiAgICAgICAgbGV0IHJlYWNoZWQgPSBBcmM6Om5ldyhBdG9taWNCb29sOjpuZXcoZmFsc2UpKTsKICAgICAgICBsZXQgbWFya2VyID0gcmVhY2hlZC5jbG9uZSgpOwogICAgICAgIGYuc2NvcGUofHwgewogICAgICAgICAgICBmYXVsdHM6Om9uY2UoUG9pbnQ6OkNsb2NrLCBtb3ZlIHx8IHsKICAgICAgICAgICAgICAgIG1hcmtlci5zdG9yZSh0cnVlLCBPcmRlcmluZzo6U2VxQ3N0KTsKICAgICAgICAgICAgICAgIG1hdGNoIGZhdWx0IHsKICAgICAgICAgICAgICAgICAgICAwID0+IHsKICAgICAgICAgICAgICAgICAgICAgICAgc3RkOjpmczo6cmVuYW1lKAogICAgICAgICAgICAgICAgICAgICAgICAgICAgZGlyZWN0b3J5LmpvaW4oIm93bmVyLmxvY2siKSwKICAgICAgICAgICAgICAgICAgICAgICAgICAgIGRpcmVjdG9yeS5qb2luKCJvcmlnaW5hbC1vd25lci5sb2NrIiksCiAgICAgICAgICAgICAgICAgICAgICAgICk/OwogICAgICAgICAgICAgICAgICAgICAgICB3cml0ZSgmZGlyZWN0b3J5LmpvaW4oIm93bmVyLmxvY2siKSwgYiJyZXBsYWNlbWVudCIpOwogICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAxID0+IHdyaXRlKAogICAgICAgICAgICAgICAgICAgICAgICAmZGlyZWN0b3J5LmpvaW4oImluZGVwZW5kZW50LWZyb250aWVyLmpzb24iKSwKICAgICAgICAgICAgICAgICAgICAgICAgYiJyZXRhaW5lZCBmb3JlaWduIHByb3Bvc2FsIiwKICAgICAgICAgICAgICAgICAgICApLAogICAgICAgICAgICAgICAgICAgIF8gPT4gd3JpdGUoJnJvb3QsICZzdXBlcjo6Y29kZWM6OmVuY29kZSgmY2hhbmdlZCwgNjU1MzYpPyksCiAgICAgICAgICAgICAgICB9CiAgICAgICAgICAgICAgICBPaygoKSkKICAgICAgICAgICAgfSk7CiAgICAgICAgICAgIGFzc2VydCEoc2VydmljZS5hbnN3ZXIoJnJhdywgZGVhZGxpbmUoKSkuaXNfZXJyKCkpOwogICAgICAgICAgICBhc3NlcnQhKHJlYWNoZWQubG9hZChPcmRlcmluZzo6U2VxQ3N0KSk7CiAgICAgICAgICAgIGFzc2VydF9lcSEoZmF1bHRzOjphZG1pc3Npb25zKCksIDApOwogICAgICAgICAgICBpZiBmYXVsdCA9PSAxIHsKICAgICAgICAgICAgICAgIGFzc2VydF9lcSEoZi5yb3coKS5hc19zbGljZSgpLCBiInJldGFpbmVkIGZvcmVpZ24gcHJvcG9zYWwiKTsKICAgICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgICAgIGFzc2VydF9lcSEoZi5yb3coKSwgb3JpZ2luYWwpOwogICAgICAgICAgICB9CiAgICAgICAgICAgIGFzc2VydF9lcSEoCiAgICAgICAgICAgICAgICBzZXJ2aWNlLmFuc3dlcigmcmF3LCBkZWFkbGluZSgpKS51bndyYXBfZXJyKCkudG9fc3RyaW5nKCksCiAgICAgICAgICAgICAgICAiTTE1IHNlcnZpY2UgaXMgZmVuY2VkIgogICAgICAgICAgICApOwogICAgICAgIH0pOwogICAgfQp9Cg=='
NOTE = '''## Native timing-fixture correction

The integrated-source-01 run on
`af6b06fa1cb944e639148b58e9765fe2bb0065ab` completed all 31 command gates.
Thirty passed. The Node release-owner gate reported 39 passed, one failed and
one existing ignored test. Its positive post-admission completion test was
refused by the conservative time check before reaching `Admitted`: the signed
fixture allowed only two trusted seconds, while its real clock advances at
twice wall-clock speed. The original failure and every other gate are retained
in the execution record; that run remains FAIL.

The test now signs one 30-trusted-second window, deliberately waits past the
former two-second setup window, and starts the original two-second service
deadline only when sending the request. At the actual `Admitted` hook it checks
that admission occurred before the signed expiry, then waits on the same real
fixture clock until that exact expiry. An independent 20-wall-second bound
prevents an unbounded test wait. The existing lost-after-durable-completion
error, committed row/frontier/floor/fence checks and cold no-redispatch checks
remain. Both negative pre-admission expiry tests remain unchanged.

This changes only test scheduling. Production clock/expiry validation, service
deadlines, crypto, wire bytes and authority transitions are unchanged. The
follow-up exact native test and complete integrated validation identify their
own corrected source commit; earlier results are not relabelled.

'''


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def blob(raw: bytes) -> str:
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def main() -> int:
    assert not OUT.exists(), 'fresh evidence directory required'
    assert digest(RUNNER.read_bytes()) == RUNNER_SHA
    spec = importlib.util.spec_from_file_location('frozen_validation', RUNNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    env = module.environment(ROOT / 'target')
    OUT.mkdir()
    shutil.copyfile(Path(__file__), OUT / 'apply-node-expiry-fixture-fix.py')
    module.save(OUT / 'environment.json', env)
    receipt = {
        'schema': 'trnm-pq-node-expiry-fixture-fix-v1', 'result': 'FAIL',
        'parent_commit': PARENT, 'branch': BRANCH, 'changed_paths': CHANGED,
        'commands': [], 'failures': [], 'production_sources_changed': False,
        'production_activation': False, 'whole_chain_pq_qualified': False,
        'exact_test_name': TEST_NAME, 'full_validation_executed': False,
    }

    def git(*args: str) -> bytes:
        return subprocess.check_output(['/usr/bin/git', '-C', str(REPO), *args],
                                       env=env, stderr=subprocess.PIPE)

    def command(label: str, argv: list[str], kind: str = 'exit') -> dict:
        result = module.run_command((label, argv, kind), REPO, OUT, env)
        receipt['commands'].append(result)
        module.save(OUT / 'receipt.json', receipt)
        assert result['passed'], 'command failed: ' + label
        return result

    try:
        prior_raw = (PRIOR / 'summary.json').read_bytes()
        assert digest(prior_raw) == PRIOR_SUMMARY_SHA
        prior = json.loads(prior_raw)
        assert prior['result'] == 'FAIL' and prior['expected_head'] == PARENT
        assert prior['source_unchanged'] and prior['provider_unchanged']
        assert prior['failures'] == [] and len(prior['commands']) == 31
        assert [c['label'] for c in prior['commands'] if not c['passed']] == ['node-release-owner']
        expected_specs = module.command_list(PARENT, PRIOR)
        for observed, (label, argv, _) in zip(prior['commands'], expected_specs, strict=True):
            assert observed['label'] == label and observed['argv'] == argv
            assert json.loads((PRIOR / (label + '.receipt.json')).read_text()) == observed
            for record in observed['logs'].values():
                assert module.file_record(Path(record['path'])) == record
        failed_stdout = PRIOR / 'node-release-owner.stdout.log'
        assert digest(failed_stdout.read_bytes()) == '788b86d0a94a827712ea707b276bb2f16b2c15cb3e20fc95fe36a4bdabd5b551'
        assert digest((PRIOR / 'node-release-owner.stderr.log').read_bytes()) == '2bc6d9def3fc2070e14f29fb04ee3ebad4bfc8d75dd8b293ba7c2dfac304e2cc'
        failed_text = failed_stdout.read_text()
        assert 'test ' + TEST_NAME + ' ... FAILED' in failed_text
        assert '39 passed; 1 failed; 1 ignored; 0 measured; 1244 filtered out;' in failed_text
        assert json.loads((PRIOR / 'sqlite-qualification.json').read_text())['passed']
        initial = module.source_identity(REPO, env)
        assert initial == json.loads((PRIOR / 'source-after.json').read_text())
        assert initial['head'] == PARENT and initial['branch'] == BRANCH and not initial['status']
        provider = module.provider_identity()
        assert provider == json.loads((PRIOR / 'provider-after.json').read_text())
        module.save(OUT / 'source-parent.json', initial)
        module.save(OUT / 'provider-parent.json', provider)
        receipt['original_failed_run'] = {
            'directory': 'integrated-source-01', 'summary': module.file_record(PRIOR / 'summary.json'),
            'source_commit': PARENT, 'result': 'FAIL', 'failed_command': 'node-release-owner',
            'failed_test': TEST_NAME,
        }
        command('preflight-before-edit', ['/bin/bash', 'scripts/project-preflight.sh'], 'preflight')

        original = (REPO / TEST_PATH).read_bytes()
        proposal = base64.b64decode(PROPOSAL_B64, validate=True)
        assert digest(original) == BEFORE_SHA and digest(proposal) == PROPOSAL_SHA
        old_report = (REPO / REPORT_PATH).read_bytes()
        assert digest(old_report) == REPORT_SHA
        (OUT / 'service-tests-before.raw').write_bytes(original)
        (OUT / 'service-tests-reviewed-proposal.raw').write_bytes(proposal)
        (OUT / 'report-before.raw').write_bytes(old_report)
        metadata = json.loads((PRIOR / 'metadata-all-features.stdout.log').read_text())
        editions = [p['edition'] for p in metadata['packages'] if p['name'] == 'trnm-pon-node']
        assert editions == ['2021']
        (REPO / TEST_PATH).write_bytes(proposal)
        command('rustfmt-reviewed-test', [str(module.TOOLCHAIN / 'bin/rustfmt'),
                                        '--edition', editions[0], str(REPO / TEST_PATH)])
        formatted = (REPO / TEST_PATH).read_bytes()
        (OUT / 'service-tests-formatted.raw').write_bytes(formatted)
        receipt['test_source'] = {
            'before': module.file_record(OUT / 'service-tests-before.raw'),
            'reviewed_proposal': module.file_record(OUT / 'service-tests-reviewed-proposal.raw'),
            'formatted': module.file_record(OUT / 'service-tests-formatted.raw'),
            'formatting_changed_bytes': formatted != proposal,
        }
        anchor = '## Binding and current-authority review\n'
        old_text = old_report.decode()
        assert old_text.count(anchor) == 1 and NOTE not in old_text
        (REPO / REPORT_PATH).write_text(old_text.replace(anchor, NOTE + anchor), encoding='utf-8')
        (OUT / 'report-after.raw').write_bytes((REPO / REPORT_PATH).read_bytes())
        corpus_file = REPO / CORPUS_PATH
        corpus = json.loads(corpus_file.read_text())
        old_corpus = json.loads(corpus_file.read_text())
        assert len(corpus['pinned_blobs']) == 722 and len(corpus['required_paths']) == 641
        assert len(corpus['assertions']) == 8 and all(v is False for v in corpus['assertions'].values())
        for path, before in [(TEST_PATH, original), (REPORT_PATH, old_report)]:
            assert corpus['pinned_blobs'][path] == blob(before)
            assert path in corpus['required_paths']
            corpus['pinned_blobs'][path] = blob((REPO / path).read_bytes())
        assert {k for k in corpus if corpus[k] != old_corpus[k]} == {'pinned_blobs'}
        assert {k for k in corpus['pinned_blobs']
                if corpus['pinned_blobs'][k] != old_corpus['pinned_blobs'][k]} == {TEST_PATH, REPORT_PATH}
        corpus_file.write_text(json.dumps(corpus, indent=2, sort_keys=True) + '\n', encoding='utf-8')
        assert sorted(git('diff', '--name-only').decode().splitlines()) == CHANGED
        assert not git('ls-files', '--others', '--exclude-standard').strip()
        command('diff-check', ['/usr/bin/git', 'diff', '--check'])
        command('ci-contract', [module.PYTHON, '-B', 'scripts/ci/check_ci_contract.py'], 'json')
        command('pq-integration', [module.PYTHON, '-B', 'scripts/ci/check_pq_research_integration.py'], 'hold-no-go')
        command('stage-reviewed-paths', ['/usr/bin/git', 'add', '--', *CHANGED])
        assert sorted(git('diff', '--cached', '--name-only').decode().splitlines()) == CHANGED
        command('staged-diff-check', ['/usr/bin/git', 'diff', '--cached', '--check'])
        command('preflight-before-commit', ['/bin/bash', 'scripts/project-preflight.sh', '--staged'], 'preflight')
        (OUT / 'source-correction.patch').write_bytes(git('diff', '--cached', '--binary', '--no-ext-diff', '--no-textconv'))
        command('commit-reviewed-fix', ['/usr/bin/git', 'commit', '-m',
                'test(m15): bind completion expiry wait to the signed window'])
        current = module.source_identity(REPO, env)
        assert not current['status'] and current['branch'] == BRANCH
        assert git('rev-parse', 'HEAD^').decode().strip() == PARENT
        assert sorted(git('diff', '--name-only', PARENT, 'HEAD').decode().splitlines()) == CHANGED
        receipt['source_commit'] = current['head']
        receipt['source_tree'] = current['tree']
        module.save(OUT / 'source-before.json', current)
        provider_before = module.provider_identity()
        assert provider_before == provider
        module.save(OUT / 'provider-before.json', provider_before)
        command('preflight-before-test', ['/bin/bash', 'scripts/project-preflight.sh'], 'preflight')
        target_result = command('node-expiry-exact-native', [module.CARGO, 'test', '--locked', '--offline',
                '--manifest-path', 'trillionnium/Cargo.toml', '-p', 'trnm-pon-node', '--lib',
                '--all-features', TEST_NAME, '--', '--exact', '--show-output', '--test-threads=1'], 'node-tests')
        rb = target_result['readback']
        assert rb['passed_names'] == [TEST_NAME] and rb['ignored_names'] == []
        assert rb['summaries'] == [[1, 0, 0, 0, 1284]] or rb['summaries'] == [(1, 0, 0, 0, 1284)]
        receipt['targeted_test'] = target_result
        after = module.source_identity(REPO, env)
        provider_after = module.provider_identity()
        module.save(OUT / 'source-after.json', after)
        module.save(OUT / 'provider-after.json', provider_after)
        receipt['source_unchanged_during_test'] = current == after
        receipt['provider_unchanged'] = provider_before == provider_after
        assert receipt['source_unchanged_during_test'] and receipt['provider_unchanged']
        sqlite = module.sqlite_qualification(ROOT / 'target', OUT)
        module.save(OUT / 'sqlite-qualification.json', sqlite)
        assert sqlite['passed']
        receipt['sqlite_qualified'] = True
        receipt['result'] = 'PASS'
    except Exception as error:
        receipt['failures'].append(f'{type(error).__name__}: {error}')
    finally:
        receipt['finished_unix_seconds'] = time.time()
        module.save(OUT / 'receipt.json', receipt)
        print(json.dumps({k: v for k, v in receipt.items()
                          if k not in ('commands', 'targeted_test', 'test_source')}), flush=True)
    return 0 if receipt['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
