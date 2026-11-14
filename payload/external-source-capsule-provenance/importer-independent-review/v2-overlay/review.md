# Importer v2: independent static delta closure

The fixed v2 driver (b691bdc0542b2a335283e59bb75954d6d7b996e42b86d4aa8db6b0af9c2c3faa, 28,961 bytes) was compared with the exact reviewed v1. Replacing only the summary schema string and inserting the seven pack-directory lines reproduces the entire v2 text byte for byte. No other source/argv/policy change is present.

The new lstat/S_ISDIR check rejects a symlink or non-directory. Canonical resolution and BASE containment guard the selected pack directory, and path/device/inode are included in every existing source snapshot. Mutable mtime/size are intentionally excluded. A missing directory refuses before any import. This closes PACK_CHILD_DIRECTORY_FENCE from the v1 independent review. It is a checked identity fence, not a filesystem transaction lock against a hostile concurrent actor.

There is no remaining static-review objection to the specified driver. The original no-network/no-ref-update command scope, effective fsck HOLD policy, exact 940-member preparation, 3,912 raw-object readback, 14-tree union and partial-failure HOLD logic are unchanged. The read-only stream child's delayed PID publication remains a nonblocking observability note.

Only static text/data review was performed. No importer function, Git command, ROG action, import, helper or test was executed. This receipt proves neither that objects were imported nor that external-evidence-contract passed.
