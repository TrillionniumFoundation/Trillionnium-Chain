# Pinned conformance dependency security

The isolated Python conformance/evidence environment pins `cryptography==50.0.2`
and `numpy==1.26.4` in `formal/pon-nakamoto-v1/requirements.txt`. The publisher's
[50.0.2 release](https://pypi.org/project/cryptography/50.0.2/) is not withdrawn,
supports Python3.9+, and its wheels update bundled OpenSSL to4.0.3 according to
the [official changelog](https://cryptography.io/en/latest/changelog/#v50-0-2).
Qualification records the actual cryptography, bundled OpenSSL and CFFI versions.
Source/evidence validation checks the measured environment against the exact pins.

## Reviewed repository alerts

The repository API on2026-10-01 reported seven open default-branch alerts for the
previous direct pin41.0.7: four high, two medium and one low. These alerts refer to
the real conformance requirements, not removed source. Updating this candidate
does not by itself close default-branch alerts or authorize a merge or launch.

| Repository alert | Publisher advisory | First patched version |
|---|---|---:|
|15|[RSA timing oracle](https://github.com/advisories/GHSA-3ww4-gg4f-jr7f)|42.0.0|
|16|[PKCS12 parsing](https://github.com/advisories/GHSA-9v9h-cgj8-h64p)|42.0.2|
|17|[PKCS12 serialization](https://github.com/pyca/cryptography/security/advisories/GHSA-6vqw-3v5j-54x4)|42.0.4|
|18|[X.509 name checks](https://github.com/pyca/cryptography/security/advisories/GHSA-h4gh-qq45-vh27)|43.0.1|
|19|[SECT subgroup attack](https://github.com/pyca/cryptography/security/advisories/GHSA-r6ph-v2qm-q3c2)|46.0.5|
|20|[DNS constraints](https://github.com/pyca/cryptography/security/advisories/GHSA-m959-cc7f-wv43)|46.0.6|
|21|[Bundled OpenSSL](https://github.com/pyca/cryptography/security/advisories/GHSA-537c-gmf6-5ccf)|48.0.1|

The new pin exceeds all seven patch thresholds. This review does not claim a
complete dependency audit or protection from future advisories. Severity totals
preserve the repository API classification where publisher classifications differ.

## Actual runtime boundary and verification

Current Python code uses raw Ed25519 keys and signatures. The reviewed sources do
not call RSA decryption, PKCS12, X.509 peer-name checking or SECT operations.
That observation narrows known trigger paths; it is not a reason to retain a
vulnerable library. Hosted conformance and historical evidence replay install
the same pinned dependencies in an isolated environment.

The native `trnm-pon-node` normal Cargo dependency graph uses `ed25519-dalek2.2.0`
and `curve25519-dalek4.1.3`; it contains neither Python cryptography nor OpenSSL.
Its Ed25519 strict checks remain independently implemented and tested. The complete
qualification must rerun RFC8032/weak-point/scalar rejection parity, native/Python
wire/state vectors, all retained regression suites and actual evidence replay after
a dependency change. Earlier measurements retain their original version records.

No dependency update grants public-work hardness, independent model efficacy,
physical power-loss assurance or production activation. The remaining gates are
in [PUBLIC_READINESS](PUBLIC_READINESS.md).
