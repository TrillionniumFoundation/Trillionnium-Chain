import argparse
import sys
import os
import time
import logging
import yaml
from executor import DockerExecutor
from listener import TaskListener
from ipfs_client import IPFSClient

# Configure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("TrillionniumWorker")

# Configuration Path
CONFIG_PATH = os.path.expanduser("~/.trillionnium/config.yaml")

def load_config():
    """Loads configuration from YAML."""
    if not os.path.exists(CONFIG_PATH):
        # Default config
        config = {
            "node_name": "worker-1",
            "private_key": "", # To be filled by user
            "ipfs_gateway": "https://ipfs.io/ipfs/",
            "rpc_endpoint": "https://rpc.sepolia.org",
            "tasks_queue": "tasks_queue.json" # MVP local queue
        }
        os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            yaml.dump(config, f)
        logger.info(f"Created default config at {CONFIG_PATH}")
        return config
    
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)

def run_worker():
    """Starts the worker daemon."""
    config = load_config()
    
    logger.info(f"Starting Trillionnium Worker [{config['node_name']}]...")
    logger.info(f"Connected to Gateway: {config['ipfs_gateway']}")
    
    # Initialize components
    # For MVP, listener uses local queue. In Phase 2, it uses Web3 Contract Events.
    listener = TaskListener(queue_file=config["tasks_queue"])
    
    # Run the loop
    try:
        listener.listen_loop()
    except KeyboardInterrupt:
        logger.info("Worker stopped by user.")

def run_test():
    """Runs a self-test of Docker capabilities."""
    print(">>> Running Self-Test...")
    executor = DockerExecutor()
    
    # Create dummy task dir
    test_path = "/tmp/trillionnium_test"
    os.makedirs(test_path, exist_ok=True)
    
    # Create simple Dockerfile
    with open(os.path.join(test_path, "Dockerfile"), "w") as f:
        f.write("FROM alpine:latest\nCMD [\"echo\", \"Hello Trillionnium\"]")
        
    print(f"Building test image in {test_path}...")
    out, code = executor.execute_task(test_path)
    
    if code == 0 and "Hello Trillionnium" in out:
        print("✅ SUCCESS: Docker is working correctly.")
    else:
        print("❌ FAILED: Docker execution failed.")
        print(f"Output: {out}")
        print(f"Exit Code: {code}")

def main():
    parser = argparse.ArgumentParser(description="Trillionnium Chain Worker CLI")
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Commands
    subparsers.add_parser("start", help="Start the worker daemon")
    subparsers.add_parser("test", help="Run self-test (Check Docker)")
    subparsers.add_parser("config", help="Show configuration path")
    
    args = parser.parse_args()
    
    if args.command == "start":
        run_worker()
    elif args.command == "test":
        run_test()
    elif args.command == "config":
        print(f"Config file located at: {CONFIG_PATH}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
