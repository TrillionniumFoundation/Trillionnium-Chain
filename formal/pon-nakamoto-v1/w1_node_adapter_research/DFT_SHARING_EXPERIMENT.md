# Request-local DFT table sharing: research experiment

The [matched receiver comparison](RECEIVER_COST_COMPARISON.md) found that
independent preprocessing dominates the measured proof-verification cost.
This candidate shares only the FFT twiddle-table owner between the two W1
components. It does not cache a verifier key or an acceptance result.

`config(component)` retains its API. `config_with_dft(component, dft)` constructs
a fresh challenger with the same fixed component domain and parameters. The
adapter gives both components clones of one request-local DFT. Both independent
public preprocessing computations, complete PCS checks, durable proof-start
reservation and native W1 admission remain paid.

The preprocessing heights are 13 and 14. Transform-shape cache keys may differ,
so this candidate may provide no useful reuse. An implementation or a passing
small test is not a measured complete-receiver improvement.

The new `dft_reuse` test uses a four-row SHA trace and an eight-row arithmetic
trace. It generates four small genuine PCS proofs and checks serialized proof
and commitment equality, fresh-configuration cross-verification, and specific
changed-public and alternative-component controls. These are not complete W1
proofs, a general security theorem or performance samples.

Measure separately built baseline and candidate binaries with identical locked
graphs and compiler flags. Outer ABBA batches should retain the original inner
NPPNNPPN comparison, fresh Node stores and charged durable owners. Retain every
failure and timeout; identify the actual source, binary, fixture and resource
owner for each observation. Whole-process wall/CPU/RSS and nested phases are
separate measurements and must not be added twice.

Missing kernel quota, memory, swap or PID readback must preserve the original
`INCOMPLETE_OR_INCOMPARABLE` outcome and null qualified medians. Descriptive raw
observations cannot qualify the original 0.25-CPU, 2-GiB, four-second service
contract. WAN traffic, queue-to-final-ACK latency, proof replacement and concrete
cryptographic qualification remain open. Qualification stays **HOLD_NO_GO**;
production activation remains false.

The previous transient workspace was reset before publication. Its unretained
executables and logs are unavailable. This reconstructed candidate needs new
exact-source validation and must not inherit historical local pass counts or
unpublished commit identities as evidence.
