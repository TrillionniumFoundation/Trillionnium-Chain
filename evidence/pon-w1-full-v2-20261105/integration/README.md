# Candidate integration verification

The proof publication is integrated over candidate `c69cf2beef9aac6a53ba9fc140cfd09f2e623fc6`, preserving all concurrent research and runtime changes. Its Rust, formal sources, Cargo graph and workflow files are unchanged by this integration. The previously present [stale inventory pin](source-pin-failure.txt) is corrected to the exact existing file; no source check is bypassed.

All 13 saved asset hashes and the executed-source Git bundle verify. The independent verifier binary SHA256 matches `9c3e3f321a24e1acb66638058fd77f67906824593422692f9e296e70a688fe65`. Using the published receipt, header and external expected artifacts, all 58 original controls replay successfully: 1 positive and 57 negative, with no timeout, panic or unexpected acceptance. [Raw replay](receipt-controls.txt). This is another verification of the same proof, not another independent proof trial.

The [30 observer tests](observer.txt) and [43 source controls](source-controls.txt) pass on the combined source. The full 7,200-second proof campaign is not rerun during integration. Source identity does not certify the newer candidate runtime or close project-wide qualification, fixed-Host confirmation, WAN or economic gates.
