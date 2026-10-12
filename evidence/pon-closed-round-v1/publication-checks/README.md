# Delivery preparation observations

The first two invocations selected an incomplete Python environment and failed
before importing the ledger because cryptography was absent. The exact original
logs remain. The corrected invocations used the existing conformance environment
(cryptography 50.0.1, numpy 1.26.4), matching the retained qualification versions.
Both then passed on byte-identical runtime sources; no assertion was relaxed.

These checks ran in the delivery checkout while only documentation and evidence
publication files were staged. They are not a new clean runtime qualification or
a substitute for exact delivery-head hosted checks. The pinned hosted environment
remains separately selected by the existing workflow requirements.
