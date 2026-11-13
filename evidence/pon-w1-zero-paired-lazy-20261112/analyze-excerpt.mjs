// Read-only numeric analysis of a manifest excerpt. This does not validate a journal.
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export function analyzeExcerpt(excerpt) {
  const names = ['full-limb-sparse-eager', 'full-limb-sparse-lazy', 'zero-paired-legacy', 'zero-paired-eager', 'zero-paired-lazy'];
  const grid = ['0:1', '0:8', '1:1', '1:8', '2:1', '3:1'];
  const axes = ['cpu_ns', 'wall_ns'];
  const need = (ok, why) => { if (!ok) throw new Error(why); };
  const count = (n, why) => { need(Number.isSafeInteger(n) && n >= 0, why); return n; };
  const clock = (n, why) => n === null ? null : count(n, why);
  const sum = xs => xs.includes(null) ? null : xs.reduce((a, b) => a + b, 0);
  const range = xs => {
    const values = xs.filter(x => x !== null);
    return {minimum: values.length ? Math.min(...values) : null,
      maximum: values.length ? Math.max(...values) : null, available: values.length,
      unavailable: xs.length - values.length, confidence_interval: false};
  };
  const fraction = (n, d) => n === null || !d ? null :
    {numerator: String(n), denominator: String(d), approximate: n / d};
  const quotient = (n, d) => {
    if (!d) return null;
    let a = n, b = d;
    while (b) [a, b] = [b, a % b];
    return {numerator: String(n / a), denominator: String(d / a), approximate: Number(n) / Number(d)};
  };
  need(Array.isArray(excerpt.cells) && excerpt.cells.length === 6, 'six excerpt cells');
  const seen = new Set();
  const cells = excerpt.cells.map(cell => {
    const key = cell.target + ':' + cell.horizon;
    need(grid.includes(key) && !seen.has(key), 'grid identity'); seen.add(key);
    need(Array.isArray(cell.arms) && cell.arms.length === 5, 'five arms');
    const costCell = cell.target < 2;
    const arms = cell.arms.map((arm, i) => {
      need(arm.name === names[i], 'fixed arm roster');
      for (const field of ['wins', 'attempts', 'misses', 'materialized', 'exhausted']) count(arm[field], field);
      need(arm.attempts === arm.wins + arm.misses, 'attempt accounting');
      need(arm.wins + arm.exhausted === 8 * cell.horizon, 'search accounting');
      need(arm.materialized === ([0, 2, 3].includes(i) ? arm.attempts : arm.wins), 'materialization accounting');
      need(Array.isArray(arm.samples_winners) && arm.samples_winners.length === 8, 'eight winner entries');
      const wins = arm.samples_winners.map(n => count(n, 'cohort wins'));
      need(wins.every(n => n <= cell.horizon) && sum(wins) === arm.wins, 'cohort winner sum');
      const result = {name: arm.name, attempts: arm.attempts, hits: arm.wins, misses: arm.misses,
        materialized: arm.materialized, exhausted: arm.exhausted, setup_calls: null,
        setup_calls_not_present_in_excerpt: true, cohort_entries: 8,
        producer_total: {}, paid_setup: {}, producer_ns_per_accepted_winner: {},
        producer_ms_per_accepted_winner: {}, cohort_ranges: {}};
      for (const axis of axes) {
        const total = clock(arm.producer[axis], 'producer total');
        const setup = clock(arm.setup[axis], 'paid setup');
        const raw = arm[axis === 'cpu_ns' ? 'samples_cpu_ns' : 'samples_wall_ns'];
        need(Array.isArray(raw) && raw.length === 8, 'eight cost entries');
        const values = raw.map(n => clock(n, 'cohort cost'));
        need(sum(values) === total, 'cohort costs sum to arm total');
        result.producer_total[axis] = total; result.paid_setup[axis] = setup;
        result.producer_ns_per_accepted_winner[axis] = fraction(total, arm.wins);
        result.producer_ms_per_accepted_winner[axis] = total === null || !arm.wins ? null : total / arm.wins / 1e6;
        result.cohort_ranges[axis] = {
          producer_total_ns: range(values),
          producer_ns_per_accepted_winner: range(values.map((v, j) => v === null || !wins[j] ? null : v / wins[j])),
          zero_winner_cohorts: wins.filter(n => !n).length};
      }
      return result;
    });
    for (const arm of arms) for (const f of ['attempts', 'hits', 'misses', 'exhausted'])
      need(arm[f] === arms[4][f], 'matched aggregate outcomes');
    const candidate = arms[4];
    const comparisons = costCell ? [2, 3, 1].map(i => {
      const ref = arms[i], factors = {};
      for (const axis of axes) {
        const r = ref.producer_total[axis], c = candidate.producer_total[axis];
        factors[axis] = r === null || c === null || !ref.hits || !candidate.hits || !c ? null :
          quotient(BigInt(r) * BigInt(candidate.hits), BigInt(c) * BigInt(ref.hits));
      }
      return {reference: ref.name, candidate: candidate.name, reference_over_candidate: factors};
    }) : [];
    return {target_index: cell.target, horizon: cell.horizon,
      purpose: costCell ? 'search-cost' : cell.target === 2 ? 'exhaustion-control' : 'first-hit-control',
      reported_counts: cell.counts, arms, fixed_aggregate_comparisons: comparisons};
  });
  need(grid.every(key => seen.has(key)), 'complete grid');
  cells.sort((a, b) => a.target_index - b.target_index || a.horizon - b.horizon);
  return {schema: 'pon-w1-zero-paired-lazy-excerpt-descriptive-analysis-v1',
    input_scope: 'numeric excerpt of a formal manifest; not a complete reader receipt',
    cells, no_cross_target_or_horizon_pooling: true, controls_not_used_as_cost_samples: true,
    no_per_sample_fastest_strategy_selection: true, cohort_ranges_are_descriptive: true,
    paired_cohort_identity_independently_verified: false, raw_journal_independently_verified: false,
    source_execution_authenticated_by_this_analysis: false, independent_sample_inference: false,
    cheapest_strategy_proven: false, production_activation: false};
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [, , inputPath, outputPath] = process.argv;
  if (!inputPath) throw new Error('Usage: node analyze-zero-paired-lazy-excerpt.mjs EXCERPT [NEW_OUTPUT]');
  const result = JSON.stringify(analyzeExcerpt(JSON.parse(readFileSync(inputPath, 'utf8'))), null, 2) + '\n';
  if (outputPath) writeFileSync(outputPath, result, {flag: 'wx'});
  else process.stdout.write(result);
}
