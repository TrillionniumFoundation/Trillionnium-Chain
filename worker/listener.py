import json
import time
import os
import logging
from executor import DockerExecutor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("WorkerListener")

class TaskListener:
    def __init__(self, queue_file="tasks_queue.json", result_file="results_queue.json"):
        self.queue_file = queue_file
        self.result_file = result_file
        self.executor = DockerExecutor()

    def listen_loop(self):
        """Polls the queue file for new tasks."""
        logger.info(f"Listening on {self.queue_file}...")
        
        while True:
            # 1. Read Queue
            if os.path.exists(self.queue_file):
                try:
                    with open(self.queue_file, "r") as f:
                        tasks = json.load(f)
                except json.JSONDecodeError:
                    tasks = []
            else:
                tasks = []

            # 2. Find Pending Tasks
            pending_tasks = [t for t in tasks if t.get("status") == "PENDING"]
            
            if not pending_tasks:
                time.sleep(2)
                continue

            # 3. Process Task
            task = pending_tasks[0] # FIFO
            task_id = task.get("id")
            source_path = task.get("source_path")
            
            logger.info(f"Processing Task ID: {task_id}")
            
            # Update status to RUNNING
            task["status"] = "RUNNING"
            self._save_tasks(tasks)

            # Execute
            stdout, code = self.executor.execute_task(source_path)
            
            # 4. Save Result
            if code == 0:
                task["status"] = "COMPLETED"
                task["result"] = stdout
                logger.info(f"Task {task_id} completed successfully.")
            else:
                task["status"] = "FAILED"
                task["error"] = "Execution failed"
                logger.error(f"Task {task_id} failed.")

            self._save_tasks(tasks)

    def _save_tasks(self, tasks):
        with open(self.queue_file, "w") as f:
            json.dump(tasks, f, indent=4)

if __name__ == "__main__":
    # Create dummy queue for test
    if not os.path.exists("tasks_queue.json"):
        dummy_task = [
            {
                "id": "test-task-001",
                "source_path": "../tasks/example_futures",
                "status": "PENDING"
            }
        ]
        with open("tasks_queue.json", "w") as f:
            json.dump(dummy_task, f)
            
    listener = TaskListener()
    try:
        listener.listen_loop()
    except KeyboardInterrupt:
        print("Worker stopped.")
