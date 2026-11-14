# Actual resume v1: progress and bounded transport change

The original invocation remains UNKNOWN. It ran for 300.068969 seconds and was stopped by its 300-second transport timeout. Both complete remote readbacks subsequently retained all 908 old heads and an absent archive tag; source before/after remained identical.

All three pre-push markers occurred once. Enumeration, counting (2916/2916), and compression (832/832) completed. The log then reports a chunked git-receive-pack POST and increasing Writing progress, ending at 1174/2208 objects, 14.50 MiB, 57 KiB/s. There is no server rejection in the retained stderr. These are local progress observations, not a claim of server acknowledgement. The 53% object count cannot estimate remaining bytes.

This evidence supports one separately authorized, bounded transmission attempt with 1800 seconds. It does not prove that 1800 seconds will be enough or diagnose the cause of the low rate. CPU samples do not establish network causation. The earlier v4 empty-output timeout remains unattributed.

The v2 patch has exactly six substitutions: driver path, schema, new evidence-name suffix, and the three matching sampled-push timeout/receipt values. Hook and readback limits, CI and protocol budgets, full source/gate checks, two-ref atomic push, fresh remote state requirements, and no-automatic-retry behavior are unchanged. This review did not execute v2; root owns its separately authorized run.
