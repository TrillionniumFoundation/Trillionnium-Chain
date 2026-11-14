# Importer v2: pack directory identity fence

This is a static preparation only. Neither importer, its helpers, nor any ROG command was executed.

The v1 source remains unchanged at SHA256 36b3b01bcba2ee13e6a1a3ca3c933f354397d99a8ee192fa136da6e083d768f2. V2 contains exactly two source edits: the receipt schema suffix becomes v2, and snapshot records and checks the actual objects/pack directory before any intended import.

The new check requires objects/pack to exist, lstat to identify a directory rather than a symlink or other file, resolve() to equal its lexical path, and that path to remain within the authorized BASE. Each snapshot records only its path, device number and inode. Directory size and timestamps are deliberately excluded because a normal object-pack import changes those values.

The original before, after-preflight, immediate-before-import and final snapshot equality checks therefore require the same pack-directory identity. Input paths and SHA/size pins, all Git argv, fsck policy, object counts, timeouts, full 3912-object readback, error/UNKNOWN handling and the single index-pack --stdin import remain unchanged.

After root review, use the same explicit CLI arguments documented for v1, with the executable filename import_external_evidence_source_capsule_v2.py and a fresh evidence directory. HEAD/tree must still be supplied from the actual intended source; no future source or successful import has been assumed.

The preserved initial static writer failure was a data-key string false positive, not an importer run. It remains in import-driver-review-v2/previous-static-writer-failure.json.
