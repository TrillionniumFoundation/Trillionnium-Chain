import subprocess
import uuid
import logging
import os
import shutil

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("WorkerExecutor")

class DockerExecutor:
    def __init__(self, work_dir="/tmp/openclaw_tasks"):
        self.work_dir = work_dir
        os.makedirs(work_dir, exist_ok=True)

    def execute_task(self, task_source_path):
        """
        Builds and runs a task from source path.
        Returns: (stdout, exit_code, result_hash)
        """
        task_id = str(uuid.uuid4())[:8]
        image_tag = f"openclaw-task:{task_id}"
        
        try:
            # 1. Build
            logger.info(f"[{task_id}] Building Docker image...")
            build_cmd = ["docker", "build", "-t", image_tag, task_source_path]
            subprocess.check_call(build_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # 2. Run (Secure Mode: No Network, Limited Memory)
            logger.info(f"[{task_id}] Running container...")
            run_cmd = [
                "docker", "run", "--rm",
                "--network", "none",      # Security: No internet access
                "--memory", "512m",       # Resource limit
                "--cpus", "1.0",
                image_tag
            ]
            
            result = subprocess.run(run_cmd, capture_output=True, text=True, timeout=300)
            
            stdout = result.stdout.strip()
            stderr = result.stderr.strip()
            exit_code = result.returncode
            
            logger.info(f"[{task_id}] Finished. Exit Code: {exit_code}")
            
            if exit_code != 0:
                logger.error(f"[{task_id}] Task Failed: {stderr}")
                return None, exit_code, None

            # 3. Cleanup
            self._cleanup_image(image_tag)
            
            return stdout, exit_code

        except subprocess.TimeoutExpired:
            logger.error(f"[{task_id}] Execution Timed Out!")
            self._cleanup_image(image_tag)
            return None, -1
        except Exception as e:
            logger.error(f"[{task_id}] System Error: {e}")
            self._cleanup_image(image_tag)
            return None, -1

    def _cleanup_image(self, tag):
        try:
            subprocess.run(["docker", "rmi", tag], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass

if __name__ == "__main__":
    # Test with local example
    executor = DockerExecutor()
    # Assuming we are in project root
    example_path = "tasks/example_futures" 
    if os.path.exists(example_path):
        print(f"Testing execution of {example_path}...")
        out, code = executor.execute_task(example_path)
        print(f"\n>>> RESULT:\n{out}")
    else:
        print(f"Path {example_path} not found. Run from project root.")
