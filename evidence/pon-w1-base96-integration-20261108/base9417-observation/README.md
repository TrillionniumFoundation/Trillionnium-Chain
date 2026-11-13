# Base 9417 after the C7 push

This fixed read-only observation fetched 9417e495165865ef6c1288b39084856e31020634 after the C7 publication. It is a direct child of 91c1b7da0f0b1f41c088d9ac0b2ee160b550b80c and changes five paths (+200/-13), including production store and historical commitment code and test bodies.

The actual merge-tree command returned exit 1 and reported conflicts in the recent-batch workflow and corpus pins. Its emitted conflict tree is not a frozen or qualified candidate. The C7 worktree stayed clean and at the same HEAD before/after. No tests or builds were run on this new tree; separate C8 integration was authorized to resolve the concrete conflicts.
