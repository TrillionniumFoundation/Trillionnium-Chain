# Retained setup failure

The first offline baseline build selected an obsolete isolated Cargo cache; resolution
failed because hex was absent. The existing correct pon-invariant-cargo cache was then
used, without changing dependencies or code. The failure was before compilation, not
a failed product test later relabelled as passing.
