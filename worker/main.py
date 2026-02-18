import argparse
import sys
import os
import time
import logging
import yaml
import fcntl
from executor import DockerExecutor
from listener import ChainListener
from ipfs_client import IPFSClient

# Configure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("TrillionniumWorker")

# Configuration Path
CONFIG_PATH = "config.yaml"

def load_config():
    """Loads configuration from YAML."""
    if not os.path.exists(CONFIG_PATH):
        logger.error(f"Config file not found at {CONFIG_PATH}. Please ensure config.yaml exists.")
        sys.exit(1)
    
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)

def run_worker():
    """Starts the worker daemon."""
    config = load_config()

    lock_path = os.path.join(os.path.dirname(__file__), ".worker.lock")
    lock_fp = open(lock_path, "w")
    try:
        fcntl.flock(lock_fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        logger.error("Another worker instance is already running. Exiting.")
        sys.exit(1)

    logger.info(f"Starting Trillionnium Worker [{config['node']['name']}]...")
    logger.info(f"Connecting to Chain: {config['node']['chain_id']}")

    listener = ChainListener(config)

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
