# Explicit reported model-generation sequence qualification

This is an additional offline check within the existing model-evidence owner,
not a new learning engine, journal, deployment service or consensus profile.
The sole development plan and all existing V1/V2 receipt domains remain unchanged.
Implementation: `formal/pon-nakamoto-v1/model_generation_sequence.py`.
Regression: `formal/pon-nakamoto-v1/test_model_generation_sequence.py`.

## Gap addressed

The existing signed consumer-decision V2 contract establishes use after its own
completed window. That statement alone permits use after the next window has
already been registered. Its generation rows also carry caller-supplied candidate
identities without accepting the complete run plans as inputs. These are explicit
limits of that narrower contract, not evidence of accepted bad production models.

`verify_generation_sequence` first runs the original signed V2 verifier without
changing its signature, receipt or history interpretation. It additionally requires:

- An expected initial model digest supplied by the existing admitted-model owner.
  A first generation cannot substitute a different predecessor for this pin.
- Three complete original run plans that pass the original plan validator and
  reproduce the run-plan identities in both the retained window and generation.
  Their actual candidate fields must match the signed candidate model identities.
- For both internal generation boundaries, predecessor consumer use strictly
  predates registration of the next window. Equality is refused because these
  timestamps contain no independent within-tick ordering evidence.

The result has its own `model-consumer-generation-sequence-v1` digest domain and
retains the original signed-decision result ID. It exposes each reported time
boundary and the initial/terminal model identities. No old input is rewritten.
No-gain and positive-gain safety/consent/resource holds remain valid no-update
outcomes; score improvement never grants local adoption authority.

## Execution and remaining evidence

Run the new regression using the repository's pinned conformance environment:

```sh
python3 formal/pon-nakamoto-v1/test_model_generation_sequence.py -v
```

The paired Hepta qualification can execute this check against its exact selected
Chain source and main-merge tree. A new source must receive its own actual tests.
Historical receipts do not qualify it. Tests use synthetic records and real test
signatures; neither constitutes prospective tasks or independent operation.

This entrypoint does not configure the ordinary Hepta task/training/selection
path. Existing owners must still supply and recheck current artifact, withdrawal,
resource and final-use authority. Signatures authenticate supplied statements,
not clocks, actual model installation, unseen tasks, hidden common control or
true consumer benefit. All original prospective, independent, model-install,
public-reward and production flags stay false; ordinary Hepta generation remains
explicitly unverified. P0 work hardness/public service, physical power loss,
long-term DA and WAN capacity retain their separate acceptance obligations.
