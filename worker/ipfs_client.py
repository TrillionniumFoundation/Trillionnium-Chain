import requests
import os
import zipfile
import logging
import io

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("IPFSClient")

class IPFSClient:
    def __init__(self, gateway="https://ipfs.io/ipfs/"):
        self.gateway = gateway.rstrip("/")

    def download_task(self, ipfs_hash, target_dir):
        """
        Downloads a ZIP file from IPFS and extracts it to target_dir.
        Returns: Path to the extracted task.
        """
        url = f"{self.gateway}/{ipfs_hash}"
        logger.info(f"Downloading task from {url}...")
        
        try:
            response = requests.get(url, stream=True, timeout=30)
            response.raise_for_status()
            
            # Check if it's a ZIP file
            content_type = response.headers.get("Content-Type", "")
            
            # Create target directory
            task_path = os.path.join(target_dir, ipfs_hash)
            os.makedirs(task_path, exist_ok=True)

            # Save content
            zip_path = os.path.join(task_path, "task.zip")
            with open(zip_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            # Extract
            logger.info(f"Extracting task to {task_path}...")
            try:
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(task_path)
                os.remove(zip_path) # Cleanup ZIP
                return task_path
            except zipfile.BadZipFile:
                logger.error("Downloaded file is not a valid ZIP.")
                return None

        except Exception as e:
            logger.error(f"Failed to download task: {e}")
            return None

    def upload_result(self, file_path):
        """
        Mock upload function. In production, this would POST to an IPFS node.
        Returns: Mock IPFS Hash.
        """
        logger.info(f"Uploading result {file_path} to IPFS...")
        # Simulate upload delay
        import time
        time.sleep(1)
        # Return a deterministic mock hash based on filename
        return f"QmResultHashMock_{os.path.basename(file_path)}"

if __name__ == "__main__":
    client = IPFSClient()
    # Test with a known IPFS hash (e.g., empty folder or test file)
    # print(client.download_task("QmTest...", "/tmp/test_download"))
