import json
import time
import os

QUEUE_FILE = "worker/tasks_queue.json"

if not os.path.exists(QUEUE_FILE):
    # Initialize if not exists
    with open(QUEUE_FILE, "w") as f:
        json.dump([], f)

def publish_batch(count=5):
    with open(QUEUE_FILE, "r") as f:
        tasks = json.load(f)
        
    print(f"Adding {count} tasks to queue...")
    
    for i in range(count):
        new_task = {
            "id": f"batch-task-{i+1}",
            "source_path": "tasks/example_futures", # Same task logic
            "status": "PENDING",
            "created_at": time.time()
        }
        tasks.append(new_task)
        
    with open(QUEUE_FILE, "w") as f:
        json.dump(tasks, f, indent=4)
        
    print("Done!")

if __name__ == "__main__":
    publish_batch()
