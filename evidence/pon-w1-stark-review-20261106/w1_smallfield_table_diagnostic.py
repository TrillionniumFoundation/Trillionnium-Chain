#!/usr/bin/env python3
"""Independent numerical evaluation of Fenzi-Sanso (2026), Table 2's RISC Zero tuple.

This is a numerical diagnostic of Corollary 4 for Construction 1. It is not
a certified global optimizer, a complete W1 attack, or quantum qualification.
No repository, external implementation, prover or network access is used.
"""
from decimal import Decimal as D, localcontext
import hashlib
import json
from pathlib import Path


def run() -> dict:
    with localcontext() as context:
        context.prec = 90
        context.Emin = -999999999
        context.Emax = 999999999
        b, e, n, rho, t = 2013265921, 4, 2 ** 21, D(1) / 4, 50
        base, field = D(b), D(b ** e)
        log_base = base.ln()

        def log_probability(delta: D) -> D:
            entropy_times_log_base = (delta * (base - 1).ln()
                                     - delta * delta.ln()
                                     - (1 - delta) * (1 - delta).ln())
            log_a = n * ((rho - 1) * log_base + entropy_times_log_base)
            log_c = (field - 1).ln() + (8 * n * delta * (1 - delta)).ln() / 2
            x = log_c - log_a
            # log(1+exp(x)), evaluated without a large positive exponential.
            softplus = x + (1 + (-x).exp()).ln() if x >= 0 else (1 + x.exp()).ln()
            return -softplus + t * (1 - delta).ln()

        low, high = D('0.000001'), D('0.999999')
        for _ in range(256):
            left, right = (2 * low + high) / 3, (low + 2 * high) / 3
            if log_probability(left) < log_probability(right):
                low = left
            else:
                high = right
        delta = (low + high) / 2
        negative_log2 = -log_probability(delta) / D(2).ln()
        conjectured = -t * rho.ln() / D(2).ln()
        assert round(negative_log2, 1) == D('92.5')
        return {
            'source_publication': 'https://cic.iacr.org/p/3/3/44',
            'source_pdf': 'https://cic.iacr.org/p/3/3/44/pdf',
            'doi': '10.62056/akdkmpxqi', 'publication_date': '2026-10-26',
            'locations': 'Corollary 4 and Remark 2: PDF page 12; Table 2: PDF page 14',
            'source_pdf_bytes_hashed': False,
            'parameters': {'base_field_size': b, 'extension_degree': e,
                           'extension_field_size': str(b ** e), 'block_length': n,
                           'rate_numerator': 1, 'rate_denominator': 4, 'queries': t},
            'method': '90-digit Decimal evaluation; 256 ternary-search iterations on a continuous delta interval',
            'delta_numerical': str(delta),
            'negative_log2_probability_lower_bound_numerical': str(negative_log2),
            'conjectured_query_only_negative_log2': str(conjectured),
            'difference_display': str(conjectured - negative_log2),
            'matches_published_one_decimal_display': True,
            'certified_global_optimization': False,
            'full_w1_attack_established': False,
            'quantum_security_bits': None,
            'scope': 'Construction 1 extension-code information-theoretic success lower bound. The FRI connection requires BSCH+26 Lemma 8.4 and list-size Corollaries 2/3; Lemma 6 does not transfer verbatim to ethSTARK.',
            'limitations': ['No known polynomial-time implementation is established by the cited paper.',
                            'n is the paper block length, not a measured W1 trace size.',
                            'This does not replace the locked component equations or subtract a loss from official 96/99 estimates.'],
            'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        }


if __name__ == '__main__':
    print(json.dumps(run(), indent=2))
