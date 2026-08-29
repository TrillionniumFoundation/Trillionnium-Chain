# W3-W7 independent light-client proof bundle v1 candidate

Status: **candidate-non-normative; bounded model only**.

A proof bundle contains exactly six families sharing one chain, height, block and application root:

| Family | Minimum candidate statement |
|---|---|
| Order | quorum-backed exact three-chain finality |
| DA | `DA-FULLREP-V1` and complete retrieval |
| Execution | canonical JMT inclusion; candidate composite-root substitution forbidden |
| Result | exact deterministic-reexecution profile and challenge maturity |
| Settlement | conservation, exactly-once terminal transition and no PoCO weight |
| Upgrade | trusted checkpoint and no downgrade |

The reference model and the independent standard-library client implement the same closed bundle contract without importing one another.

This bundle does not replace the existing bounded raw CEV1 Order/light-client checkers. Production closure additionally requires exact canonical byte decoding, strict signature verification, validator-set transitions, malformed-proof fuzzing, proof size/time budgets, 64-epoch/10,000-header progression and independent production implementations.

Subjective evidence may be displayed only as subjective. It is invalid as objective result, settlement or PoCO-weight proof.
