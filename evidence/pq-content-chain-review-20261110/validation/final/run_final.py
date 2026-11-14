import json,subprocess
checks=[['python3','-B','scripts/ci/test_pq_content_chain_review.py','-v'],['python3','-B','scripts/ci/pq_content_chain_review.py'],['python3','-B','scripts/ci/check_ci_contract.py'],['python3','-B','scripts/ci/check_pq_research_integration.py'],['python3','-B','scripts/ci/check_repository.py'],['python3','-B','scripts/refresh_distributed_source_inventory.py','--check']]
for argv in checks:
 print(json.dumps({'running':argv}),flush=True);subprocess.run(argv,check=True)
print(json.dumps({'completed_commands':len(checks),'native_tests_executed':False,'production_activation':False}),flush=True)
