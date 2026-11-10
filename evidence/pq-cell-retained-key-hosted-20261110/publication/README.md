# Actual local-channel evidence publication

The already published evidence-only commit is `ee48626f687614d95782cafbd1ea15a397abfe34`, tree `058eed239851d6dfd0f15f65a5f2a96a10fb11ec`, parent `a4c594fc9d5f43d0d2b7ae7e0835d0e1514dc667`.

The retained first durable-job stderr and second terminal failure show TCP connection timeouts during fixed content-addressed blob uploads. No failed observation was rewritten. The successful third terminal also retains its first object-upload timeout, followed by one bounded retry and the exact final result. Its terminal exit is zero with complete output.

The actual publisher is retained here. Its only adapter change from the original v2 template adds at most three transport attempts for fixed content-addressed blob/tree/commit POSTs. Ref and PR updates are not automatically retried. Repository ID, ProfHepta identity/admin, draft PR, expected old head, exact tree/commit and single parent checks remain. It used the Mac local `/opt/homebrew/bin/gh`, an ordinary fast-forward, and no production activation. No alternate SSH or ROG write route was used.

The [PR readback](remote-pr-readback.json) and [commit readback](remote-commit-readback.json) were obtained after publication. The latter is parsed metadata with its original terminal archive identity/hash; it is not a new native execution or a full raw terminal transcript. All native source qualifications remain attached to a4. This packet does not claim every hosted gate passed.
