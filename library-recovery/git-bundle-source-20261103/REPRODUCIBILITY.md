# Historical Git bundle source custody

This directory preserves exact source variants recovered from historical Git
bundles. Each variant is stored below its original Git blob object ID, followed
by its original repository path. The containing branch is isolated from the
default branch. The source manifest maps every preserved byte stream to its
original source path, original commit, archive member, bundle SHA256, file
SHA256, and Git blob SHA1.

## Verification and restoration

For any entry in SOURCE_MANIFEST.json, obtain the file at `recovery_path` from
this branch. Its byte length must equal `bytes`; `sha256sum` must equal `sha256`;
and `git hash-object --no-filters` must equal `git_blob_sha1`. The original file
mode is recorded in `original_locations`. Recovery files are stored as regular
text files so they remain inert until explicitly restored into a separate worktree.

Multiple historical variants of one path coexist. Choose the intended historical
commit and restore only the matching variant into a separate worktree with that
revision's dependencies. This custody directory is not a ready-to-build merged
source snapshot. The missing original commit objects have not been recreated on
a branch, and no build, test, CI acceptance, or production readiness is claimed.

All fourteen genuine Git bundles were decoded without executing their contents.
Git independently verified their packs and all 836 decoded object byte streams.
Every external delta base was resolved, including the owning HTTP candidate whose
repository is hepta-private-ci. All bundle prerequisites were found in their
correct remote repositories. Already remotely reachable source and source owned
by the aggregate archive publication are tracked in the aggregate audit rather
than duplicated here.

Original mixed-content bundles contain historical runtime outputs and are not
republished by this change. Source files, workflow source stored under this inert
recovery prefix, and this reproducibility manifest are the complete upload scope.
