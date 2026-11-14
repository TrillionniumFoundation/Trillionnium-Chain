# H5DF service-model failures: outer evidence only

The six authorized GET requests all completed in 71.043604 seconds. Each original job has one failed step: #7, Execute original release from-zero controls. The Host controller records successful formatting/build preparation, systemd_run_exit=1 and passed=false, with failure=null and final_host_errors=[].

The native failure cause remains UNKNOWN. These outer logs do not contain the native manifest or the searched confirmation/deadline/test-failure codes. No artifact was requested. Existing H5DF cross-cost or R1 failures are not used as causes for these three jobs. They are outside the fourteen required jobs.

Actual source is taken from each complete log. Both head jobs identify 5df7ae6f482157c5f7fdcbcd52222117a965053f. The ARM prospective job identifies a590178fa1ba11fc1419ea60de1f7f5633a70cfd, with H5DF candidate and dd6e1c3cbeacbdc532b0679297835b3a0aac78f0 base. All before/after records have tree 6be4940d38cc88782657f2684cbefe48866f8b9f, 41681 entries and 3995072357 bytes. Nested preparation records use kind=head for the actual checked-out commit; they are preserved separately from the top-level candidate/base/prospective source record.

Later debug pressure, CLI, service CPU/cancellation and model lifecycle steps succeeded. Panic text from those successful controls is not promoted to the earlier release failure. Exact step names/times, source records, command, original log line numbers and upload artifact identities are in exact-outer-facts.json and original-line-excerpts.json.

The proposed next acquisition is limited to the x64 job's own manifest via verified positive ranges, after fresh artifact metadata. It has NOT been executed. Neither that job nor either ARM job has an established inner failure class from this review.

No Git/source/ref/stage modifications, tests, CI actions or additional network calls were performed in the offline review. Existing acquisition-summary.json is unchanged, including its original pre-analysis actual_tested_source_verified=false value. This review adds evidence from the subsequently parsed original logs without rewriting that receipt.
