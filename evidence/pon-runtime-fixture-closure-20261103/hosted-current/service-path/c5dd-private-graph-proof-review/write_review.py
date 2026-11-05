#!/usr/bin/env python3
"""Write a static review from already verified source receipts; no native run."""
from pathlib import Path
import hashlib
import json

OUT = Path(__file__).resolve().parent
sources = json.loads((OUT / 'source-identities.json').read_text())

def ref(path, lines, fact):
    return {'path': path, 'lines': lines, 'fact': fact,
            'source_commit': sources['measured_source']}

io = 'trillionnium/crates/trnm-sqlite-io-boundary/src/'
node = 'trillionnium/crates/trnm-pon-node/src/'
sqlite = sources['pinned_dependency_sources'][0]
review = {
    'schema': 'private-cross-cursor-graph-dependency-proof-static-review-v1',
    'verdict': 'NO_GO_WITH_CURRENT_OBSERVER_OWNER_AND_REQUESTED_INVALIDATION_CONTRACT',
    'source_receipts': {
        'file': 'source-identities.json',
        'sha256': hashlib.sha256((OUT / 'source-identities.json').read_bytes()).hexdigest(),
        'measured_source': sources['measured_source'],
        'followup_source': sources['followup_source'],
        'all_17_reviewed_repository_paths_byte_equal': all(x['bytes_equal'] for x in sources['files']),
        'sqlite': {k: sqlite[k] for k in ('package', 'version', 'sqlite_version', 'sqlite_source_id', 'sha256', 'archive_sha256')},
    },
    'scope': {
        'question': 'Can a new private proof, limited to one original resume_intent call and current generation, safely reuse a completed account graph across precisely controlled non-account cursor transactions without changing existing receipts, storage authority, crash/cut/cancellation semantics or live checks?',
        'requested_fail_closed_events': ['unknown SQL', 'DDL', 'no-row writing attempts', 'rollback', 'transaction ABA', 'external connection writes', 'schema changes', 'observer replacement or overflow'],
        'no_new_native_or_sqlite_execution': True,
        'no_patch_or_production_source_or_target_modification': True,
        'named_tests_below': 'Retained source-level contracts, not newly executed controls.',
        'no_qualification_or_speedup_claim': True,
        'not_a_universal_impossibility_claim': 'A different enforced writer ownership and dependency observation design could be separately proposed and qualified. Current trace/owner alone does not provide that design.',
    },
    'decision': {
        'decisive_gap': 'The proposed certificate must cross COMMIT gaps where the original SQLite writer lock is released. A raw second SQLite connection is within the retained fault surface. The current connection-local trace cannot observe its attempted no-row writes or rolled-back writes. Unchanged current graph bytes, state, generation and data_version do not certify the absence of those required invalidation events. This is a static coverage/indistinguishability argument; no new exploit or native negative control was run.',
        'data_version_limit': 'The pinned SQLite source uses u32 pager/Btree data-version arithmetic, not a globally monotone checked event journal. Reading that value into u64 does not create sticky overflow detection or history of foreign attempted SQL. Equality is a useful change observation but insufficient for all requested invalidation facts.',
        'existing_receipt_not_relaxed': 'PostWriteReadback remains restricted to its actual original writer and no-write epoch. It must not be re-stamped after COMMIT or after a permitted-looking statement, and a partial frontier must not become a whole-graph receipt.',
        'cost_benefit': 'There is real repeated account-graph work in the retained workload, but its 71 account_graph calls combine full/partial roles and imports. No per-role saved-cost estimate or cross-cursor candidate performance was measured. The observed cost does not justify weakening the above invalidation contract.',
    },
    'findings': [
        {
            'id': 'foreign_gap',
            'classification': 'decisive_for_the_requested_contract',
            'finding': 'Node owner.lock is cooperative process ownership, not continuous exclusion of arbitrary SQLite writers. Every original atomic_reorg_with_readback commits before the next cursor cut/transaction. The retained foreign-writer test explicitly opens a raw second connection, proves DatabaseBusy under the original writer, then mutates archive_nodes after commit and requires owner stop on the fresh read.',
            'evidence': [
                ref(node + 'store.rs', '1350-1370, 1521', 'owner.lock ownership and WAL database setup'),
                ref(node + 'store.rs', '5021-5073', 'BEGIN IMMEDIATE, original owner and final write fences, COMMIT'),
                ref(node + 'store/reorg_readback_tests.rs', '635-687', 'original_write_lock_blocks_foreign_writer_and_no_scope_survives_commit'),
                ref(io + 'transaction_scope.rs', '53-55', 'Another connection has a separate observer and does not change this observer'),
            ],
            'consequence': 'The new proof cannot safely treat a same-generation owner.lock holder as a certificate that no foreign operation happened between cursor transactions. Retaining an SQLite writer lock across the gaps would change the original transaction/cut contract rather than solve this inside the proposed private proof.',
        },
        {
            'id': 'data_version',
            'classification': 'insufficient_external_history_identity',
            'finding': 'The actual bundled SQLite 3.51.3 source stores Pager.iDataVersion as u32, increments it without checked sticky overflow, returns it as u32, and combines it with per-Btree iBDataVersion. Own commits compensate the local Btree offset. It is computed by the pager, not a durable global database revision.',
            'pinned_source_lines': {
                '59592': 'Pager iDataVersion is u32',
                '60693-60703': 'pager_reset increments; sqlite3PagerDataVersion returns u32',
                '71768': 'Btree iBDataVersion is u32',
                '76839-76844': 'Own commit compensation',
                '82847-82864': 'Not stored in database; u32 result is pager version plus Btree offset',
            },
            'source_identity': sqlite['sha256'],
            'not_claimed': ['No wrap was observed or executed.', 'No claim that one increment equals one foreign transaction.', 'No external no-row or rollback experiment was run.'],
            'required_but_not_sufficient_sampling': 'If used as one defense in a future design, sample on the same connection after acquiring the next actual BEGIN IMMEDIATE and before reuse; do not sample only before acquiring the lock, and do not reset the certificate after an observed mismatch. This still does not prove all required events absent.',
        },
        {
            'id': 'coarse_trace',
            'classification': 'new_owner_protocol_required',
            'finding': 'Current STMT observation provides private connection/process identity and checked statement/write/control counters. It intentionally counts attempted writes before their outcome. It does not expose table dependencies, bound parameters, affected rows, successful completion, or a token binding one statement to an authorized owner operation. A counter delta cannot distinguish an approved cursor mutation from an unknown write with the same count.',
            'evidence': [
                ref(io + 'transaction_scope.rs', '14-30, 125-185, 206-244', 'Private owner state, single trace installation, live probe, attempted execution counters'),
                ref(io + 'transaction_scope.rs', '72-98', 'Same actual WRITE transaction and no potentially writing SQL since capture'),
                ref(io + 'transaction_scope_tests.rs', '246-289', 'Failed/no-row/reversed DDL and prepared writes remain invalidating'),
            ],
            'precompiled_statement_assessment': 'Already prepared/reused statements are observed at execution by the existing trace. This is a supported capability, not a missed-existing-statement bug. A new preparation-only SQL authorizer would not by itself replace the original execution evidence.',
            'precompiled_evidence': ref(io + 'transaction_scope_tests.rs', '79-92, 268-289', 'Cached/prepared controls and writes observed at execution'),
            'new_design_obligations': 'Any new local dependency journal would need exact privately nominated statement identity and operation lifetime, bounded bindings and expected affected-row checks, successful completion acknowledgment, sticky rejection of all other writes/controls, and independent observer liveness. That is a new ownership protocol; none is supplied by the existing write counter.',
        },
        {
            'id': 'hooks',
            'classification': 'non_additive_hooks_and_missing_coverage',
            'finding': 'SQLite allows one trace callback per connection; a second trace replaces the first. The current native boundary installs an authorizer and the cancellation cleanup installs another specialized authorizer/progress handler. New hook installation must be integrated under the existing owner and lifecycle. It cannot assume hooks compose or overwrite an existing policy.',
            'pinned_source_lines': {
                '3885-3903': 'STMT is beginning-of-statement; PROFILE supplies completion timing, not a full successful-row proof',
                '3934-3937': 'Trace registrations override previous trace callbacks',
                '7438-7486': 'Update-hook row coverage and omissions',
                '11008-11024': 'Preupdate hook requires compile feature and has table coverage restrictions',
                '124180-124193': 'set_authorizer replaces callback/context and may expire prepared statements',
            },
            'evidence': [
                ref(io + 'sql.rs', '91-118, 136-168', 'Native boundary transaction observer and authorizer'),
                ref(node + 'store/reorg_cancellation.rs', '39-80, 393-408', 'Specialized cleanup authorizer/progress ownership and cleanup'),
                ref(io + 'transaction_scope_tests.rs', '147-155', 'Replacing trace is detected by a real execution probe'),
            ],
            'consequence': 'Per-row hooks also miss no-row/failed statements and do not observe other connections. They cannot replace the current attempted-execution fencing. This review does not assert the preupdate feature is already enabled or qualified.',
        },
        {
            'id': 'schema_and_vm',
            'classification': 'fresh_normalization_not_historical_proof',
            'finding': 'The existing contract explicitly excludes general immutability for prepare-time PRAGMA effects, Blob/backup, indirect UDF/virtual-table effects. PostWriteReadback freshly checks ordinary main/temp schema and executes writable_schema=RESET through DONE before its first graph, handling catalog/cached-VM divergence. Equal final catalog or schema_version cannot alone prove no unknown/DDL/ABA action happened across a released transaction.',
            'evidence': [
                ref(io + 'transaction_scope.rs', '78-82', 'Declared coverage boundary'),
                ref(node + 'store/native_authenticated/post_write_readback.rs', '45-80, 121-155', 'Fresh namespace/schema and RESET normalization'),
                ref(node + 'store/native_authenticated/post_write_readback/fence_tests.rs', '134-190', 'Retained catalog and cached-VM divergence negative control source'),
            ],
            'consequence': 'A future proof must retain actual schema/VM normalization, no extra attached or temp objects, original ordinary tables, and fail closed on unsupported API/SQL. This does not repair the foreign-history gap.',
        },
        {
            'id': 'scope_and_generation',
            'classification': 'eligible_scope_smaller_than_nine_transactions',
            'finding': 'The durable intent transaction and its cut finish before the original resume_intent_with_progress call. A proof confined to that call cannot inherit the intent graph. During the cursor loop active remains (old,g-1), while the final transaction publishes active generation g. A current-generation proof cannot be silently rebound to g across that publication.',
            'evidence': [
                ref(node + 'store.rs', '5228-5307', 'Intent commit and cut precede resume call'),
                ref(node + 'store.rs', '5431-5471', 'Fresh durable row, active generation check and steps check'),
                ref(node + 'store.rs', '5472-5504', 'Separate immediate transaction and commit-before-cut per cursor'),
                ref(node + 'store.rs', '5505-5575', 'Fresh final state checks and atomic active/generation/slot publication'),
            ],
            'consequence': 'Do not describe all nine original transactions as reusable under a one-resume/current-generation scope. Any hypothetical eligible prepublication cursor subsequence would require its own independently established proof, and final publication invalidates it.',
        },
        {
            'id': 'original_business_and_progress',
            'classification': 'must_remain_fresh_and_unchanged',
            'finding': 'Current State/Record/delta/full commitment comparison, original row preimages and rowcount guards, actual transaction completion, final owner and write fences, cancellation/Host checks, crash cuts and durable cursor remain mandatory. Whole-graph mathematical equality is not an authority to accept stale storage or replace current input checks.',
            'evidence': [
                ref(node + 'store/native_authenticated/post_write_readback.rs', '82-94, 179-214, 226-254, 301-345', 'Bounded role nomination; fresh complete-state check; whole graph only; consumed-result and last-write fences'),
                ref(node + 'store/native_authenticated.rs', '748-762', 'Partial frontier does not nominate a whole graph'),
                ref(node + 'store.rs', '5094-5133', 'Delta preimage, rowcount and progress checks'),
                ref(node + 'store/reorg_cancellation.rs', '355-377, 380-483', 'Typed cancellation selection and cleanup against actual durable cursor'),
                ref('docs/protocol/pon-nakamoto-v1/details/PERFORMANCE_ACCEPTANCE.md', '65-109', 'Original acceptance/source/workload/budget and semantic boundaries'),
            ],
            'relation_to_group_commit': 'The separate group-commit review rejects changed durable prefixes/cuts/cancelled_cursor. A dependency proof that preserved those boundaries is a distinct proposal, but it still fails the observation/ownership sufficiency conditions above. This review does not propose grouping commits.',
        },
    ],
    'measurement_limits': {
        'retained_workload_context': 'The independently retained H4-to-H11 case has intent + seven attach transactions + final publication. Account-root repetition is an opportunity signal; State and non-account roots still vary.',
        'graph_aggregate': '71 account_graph calls and their nested time combine different full/partial roles across imports. This review does not assign all calls or all time to cursor transactions or forecast savings.',
        'host_aggregate': '29,928 Host checkpoints belong to the whole complete-page import, not activation alone; thread CPU is nested and cannot be added to caller CPU or used as an exact percentage.',
        'no_new_timings_or_benchmark': True,
    },
    'possible_future_direction_without_approval_to_implement': {
        'boundary': 'Only a separately specified and measured ownership/dependency design that actually supplies the missing external event or exclusion proof could reopen cross-cursor reuse. It must retain all current foreign-writer, rollback, no-row, schema, generation, source, cancellation and durable-prefix behavior.',
        'not_sufficient': ['Same accountRoot or unchanged active generation alone', 'Same owner.lock holder alone', 'Unchanged current data_version alone', 'Allowed table names or the number of executed writes alone', 'Re-stamping PostWriteReadback after an allowed-looking operation', 'A new trace/authorizer installed beside existing hooks', 'Promoting partial graph receipts or cached authorization'],
        'smaller_existing_boundary': 'If exploring independent improvements, keep them inside a currently proven writer/no-write epoch or a single immutable input computation, preserve actual current observations, and measure their own cost before production changes. No implementation recommendation or performance qualification is made here.',
    },
    'retained_reader_attempt': {
        'first_attempt': 'collector-attempt-1 preserved exact script/stderr and exit 1: local registry has no .cargo-checksum.json. This is a source-reader assumption failure, not a native or project test result.',
        'corrected_attempt': 'Existing .crate archives were verified against exact Cargo.lock package checksums and extracted source members were byte-compared with local primary sources. All 17 c5/b4 path pairs matched; collector exit 0.',
        'no_redownload': True,
    },
    'related_existing_evidence': sources['related_existing_readbacks'],
}
(OUT / 'review.json').write_text(json.dumps(review, indent=2, ensure_ascii=False) + '\n')
items=[]
for path in sorted(OUT.rglob('*')):
    if path.is_file() and path.name not in ('artifact-index.json', 'verification.json'):
        raw=path.read_bytes()
        items.append({'path': str(path.relative_to(OUT)), 'bytes': len(raw),
                      'sha256': hashlib.sha256(raw).hexdigest()})
index={'schema':'static-review-artifact-index-v1','files':items,
       'total_file_bytes':sum(x['bytes'] for x in items),
       'no_native_or_sqlite_execution':True,
       'no_source_or_target_modification':True}
(OUT / 'artifact-index.json').write_text(json.dumps(index, indent=2)+'\n')
print(json.dumps({'verdict':review['verdict'], 'review_bytes':(OUT/'review.json').stat().st_size,
                 'review_sha256':hashlib.sha256((OUT/'review.json').read_bytes()).hexdigest(),
                 'indexed_files':len(items), 'indexed_bytes':index['total_file_bytes'],
                 'index_sha256':hashlib.sha256((OUT/'artifact-index.json').read_bytes()).hexdigest()}))
