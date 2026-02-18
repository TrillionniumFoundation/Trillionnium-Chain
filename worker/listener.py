import time
import logging
import json
import sys
import os
import requests
import subprocess
import hashlib
from pathlib import Path
from executor import DockerExecutor

# Add proto_out to path
sys.path.append(os.path.join(os.path.dirname(__file__), "proto_out"))

# Import generated proto classes
try:
    from chain.compute.tx_pb2 import MsgCompleteJob
    HAS_PROTO = True
except Exception as e:
    logging.warning(f"Generated proto classes unavailable: {e}")
    HAS_PROTO = False

# Configure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("WorkerListener")

class ChainListener:
    def __init__(self, config):
        self.config = config
        self.executor = DockerExecutor()
        self.grpc_endpoint = config['node']['grpc_endpoint']
        self.rpc_endpoint = config['node']['rpc_endpoint']
        self.chain_id = config['node']['chain_id']
        
        # Wallet placeholder (for future signed submit)
        self.wallet_addr = config['node'].get('address', 'worker-addr-not-set')
        self.key_name = config['node'].get('key_name', 'alice')
        self.chain_bin = config['node'].get('chain_binary', '/Users/qianqi/.openclaw/workspace/TrillionniumChain/build/chaind')
        self.home = config['node'].get('home', '/Users/qianqi/.chain')
        logger.info(f"Worker wallet configured: {self.wallet_addr} (key={self.key_name})")

        self.last_height = 0
        self.state_file = Path(os.path.join(os.path.dirname(__file__), "worker_state.json"))
        self.seen_jobs = set()
        self.in_flight_jobs = set()
        self.sequence = None
        self._load_state()

    def listen_loop(self):
        """Polls the chain for new compute jobs."""
        logger.info(f"🚀 Worker Listener started. Connected to {self.chain_id} via {self.rpc_endpoint}")
        
        # Ensure worker identity is registered in workload module (idempotent)
        self.ensure_worker_registered()

        # Get current height to start listening from "now"
        try:
            self.last_height = self._rpc_height()
            logger.info(f"Synced at block height: {self.last_height}")
        except Exception as e:
            logger.error(f"Failed to get chain status: {e}")
            return

        while True:
            try:
                # Poll for new blocks
                current_height = self._rpc_height()
                
                if current_height > self.last_height:
                    # Process blocks from last_height+1 to current_height
                    for h in range(self.last_height + 1, current_height + 1):
                        self.process_block(h)
                    
                    self.last_height = current_height
                
                time.sleep(2) # Poll interval
                
            except KeyboardInterrupt:
                logger.info("Stopping listener...")
                break
            except Exception as e:
                logger.error(f"Error in listen loop: {e}")
                time.sleep(5)

    def _load_state(self):
        try:
            if self.state_file.exists():
                data = json.loads(self.state_file.read_text())
                self.seen_jobs = set(data.get("seen_jobs", []))
                self.sequence = data.get("sequence")
        except Exception:
            self.seen_jobs = set()
            self.sequence = None

    def _save_state(self):
        try:
            self.state_file.write_text(json.dumps({
                "seen_jobs": sorted(list(self.seen_jobs)),
                "sequence": self.sequence,
            }, ensure_ascii=False, indent=2))
        except Exception as e:
            logger.warning(f"Failed to save state: {e}")

    def _rpc_height(self):
        r = requests.get(f"{self.rpc_endpoint}/status", timeout=5)
        r.raise_for_status()
        return int(r.json()["result"]["sync_info"]["latest_block_height"])

    def _query_sequence(self):
        cmd = [
            self.chain_bin, "query", "auth", "account", self.wallet_addr,
            "--output", "json",
            "--home", self.home,
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(r.stderr or r.stdout)
        data = json.loads(r.stdout)
        seq = int(data["account"]["value"]["sequence"])
        self.sequence = seq
        self._save_state()
        return seq

    def ensure_worker_registered(self):
        """Idempotently register worker in workload module so compute claim won't fail with worker-not-found."""
        try:
            ok = self._run_chain_tx([
                "tx", "workload", "register-worker",
                self.key_name,
                f"ipfs://worker-{self.key_name}",
                "--from", self.key_name,
                "--keyring-backend", "test",
                "--chain-id", self.chain_id,
                "--yes", "--gas", "auto", "--gas-adjustment", "1.5",
            ])
            if ok:
                logger.info("Worker registration ensured")
        except Exception as e:
            logger.warning(f"ensure_worker_registered skipped: {e}")

    def process_block(self, height):
        """Fetches block results and looks for 'new_compute_job' events."""
        try:
            r = requests.get(f"{self.rpc_endpoint}/block_results?height={height}", timeout=8)
            r.raise_for_status()
            data = r.json().get("result", {})
            txs_results = data.get("txs_results") or []

            for txr in txs_results:
                events = txr.get("events") or []
                for ev in events:
                    if ev.get("type") != "new_compute_job":
                        continue
                    attrs = {}
                    for a in ev.get("attributes", []):
                        k = a.get("key")
                        v = a.get("value")
                        if k is not None:
                            attrs[k] = v
                    self.handle_job_event(attrs)

        except Exception as e:
            logger.error(f"Failed to process block {height}: {e}")

    def handle_job_event(self, attributes):
        """Parses the event and triggers execution."""
        raw_job_id = attributes.get("job_id")
        payload = attributes.get("payload")
        requirements = attributes.get("requirements", "")

        jid = str(raw_job_id).strip().strip('"').strip("'")
        digits = ''.join(ch for ch in jid if ch.isdigit())
        job_id = digits if digits else jid

        if job_id in self.seen_jobs or job_id in self.in_flight_jobs:
            return
        self.in_flight_jobs.add(job_id)

        logger.info(f"🔔 New Job Detected! ID: {job_id} | Payload: {payload}")
        
        # Validate requirements (Mock check)
        if "gpu" in requirements and "gpu" not in self.config['worker']['capabilities']:
            logger.warning(f"Skipping Job {job_id}: Missing GPU capability.")
            self.in_flight_jobs.discard(job_id)
            return

        # Claim job on-chain first (set status=RUNNING and assigned_worker)
        if not self.request_job_execution(job_id):
            logger.warning(f"Skip Job {job_id}: failed to claim execution rights")
            self.in_flight_jobs.discard(job_id)
            return

        # Trigger Execution
        logger.info(f"⚙️ Starting execution for Job {job_id}...")
        
        # Here we would download the payload from IPFS
        # source_path = self.download_payload(payload) 
        # For prototype, we assume payload is a direct path or dummy string
        
        # Mocking execution for the event payload
        # In real world: ipfs_client.get(payload) -> /tmp/job_id/
        
        # Execute
        # stdout, code = self.executor.execute_task(source_path)
        
        logger.info(f"✅ Job {job_id} processing started.")
        
        # 1. Download payload (Mock: assume it's a local path or simple script)
        # If payload starts with 'ipfs://', download it.
        # For now, we assume payload is a folder path relative to workspace
        
        # 2. Execute
        stdout, code = self.executor.execute_task(payload)
        
        # 3. Submit Result
        if code == 0:
            logger.info(f"Task succeeded. Result: {stdout[:50]}...")
            # wait a couple blocks so RUNNING-state tx is committed before complete-job
            time.sleep(3)
            committed = self.submit_result(job_id, stdout)
            if committed:
                self.seen_jobs.add(job_id)
                self._save_state()
        else:
            logger.error(f"Task failed. Code: {code}")
            # Optionally submit failure report

        self.in_flight_jobs.discard(job_id)

    def _run_chain_tx(self, args):
        def run_once():
            cmd = [self.chain_bin] + args + ["--home", self.home, "--broadcast-mode", "sync"]
            r = subprocess.run(cmd, capture_output=True, text=True)
            out = (r.stdout or "") + (r.stderr or "")
            ok = (r.returncode == 0) and (
                "code: 0" in out or '"code":0' in out or '"code": 0' in out
            )
            return ok, r, out, cmd

        benign_markers = [
            "already registered",
            "not in CREATED state",
            "not found in workload module",
        ]
        quiet_benign_markers = [
            "worker already registered",
        ]

        for attempt in range(6):
            ok, r, out, cmd = run_once()
            if ok:
                return True
            if "account sequence mismatch" in out:
                time.sleep(0.8 + attempt * 0.3)
                continue
            if any(m in out for m in benign_markers):
                if any(m in out for m in quiet_benign_markers):
                    logger.debug("Worker already registered; skip re-register")
                else:
                    logger.info(f"Benign tx skip: {' '.join(cmd)}\n{out.strip()}")
                return False
            break

        logger.error(f"TX failed rc={r.returncode}: {' '.join(cmd)}\n{out}")
        return False

    def request_job_execution(self, job_id):
        return self._run_chain_tx([
            "tx", "compute", "request-job-execution",
            "--job-id", str(job_id),
            "--from", self.key_name,
            "--keyring-backend", "test",
            "--chain-id", self.chain_id,
            "--yes", "--gas", "auto", "--gas-adjustment", "1.5",
        ])

    def submit_result(self, job_id, result):
        """Broadcast MsgCompleteJob via chaind CLI."""
        try:
            result_hash = hashlib.sha256((result or "").encode()).hexdigest()
            logger.info(f"Submitting MsgCompleteJob for Job {job_id} result_hash={result_hash[:16]}...")
            ok = self._run_chain_tx([
                "tx", "compute", "complete-job",
                "--job-id", str(job_id),
                "--result", result_hash,
                "--from", self.key_name,
                "--keyring-backend", "test",
                "--chain-id", self.chain_id,
                "--yes", "--gas", "auto", "--gas-adjustment", "1.5",
            ])
            if ok:
                logger.info(f"✅ Job {job_id} result committed on-chain")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to submit result: {e}")
            return False

