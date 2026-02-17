import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# --- CRYPTO PRIMITIVES (SIMULATED TEE) ---

class TEEWorker:
    def __init__(self, name):
        self.name = name
        # Generate keypair inside the "Enclave"
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        
        # Hardware ID (Simulated)
        self.enclave_id = hashlib.sha256(f"SGX_{name}".encode()).hexdigest()

    def get_attestation_report(self):
        """Returns public key + proof that it's from a TEE."""
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # In reality, this report is signed by Intel/AMD hardware key
        report = {
            "enclave_id": self.enclave_id,
            "public_key": base64.b64encode(pem).decode('utf-8'),
            "is_secure": True
        }
        return report

    def process_secure_task(self, encrypted_data):
        """Decrypts, processes, and re-encrypts result inside TEE."""
        print(f"[{self.name}] Received encrypted payload. Decrypting inside Enclave...")
        
        try:
            # 1. Decrypt
            plaintext = self.private_key.decrypt(
                encrypted_data,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            print(f"[{self.name}] Decrypted: {plaintext.decode()}")
            
            # 2. Process (Simulate sensitive calculation)
            # E.g., analyzing financial data
            result = f"Analyzed: {plaintext.decode()} -> PROFITABLE"
            
            # 3. Encrypt Result (using User's public key - simplified here as symmetric for demo)
            # For demo, we just return the string, assuming a secure channel back
            return result
            
        except Exception as e:
            return f"Error: {str(e)}"

# --- SIMULATION FLOW ---

def run_phase3_simulation():
    print("--- PHASE 3: Privacy-Preserving TEE Computation ---\n")

    # 1. Worker initializes TEE
    worker = TEEWorker("Intel-SGX-Node-01")
    report = worker.get_attestation_report()
    print(f"Worker Attestation: Enclave ID={report['enclave_id'][:8]}...")
    
    # 2. User verifies attestation (On-chain check)
    if not report['is_secure']:
        print(">>> USER: Worker is not secure! Abort.")
        return
    
    # 3. User encrypts sensitive data
    user_secret = "Company Revenue: $50M"
    print(f"\n>>> USER: Encrypting secret: '{user_secret}'")
    
    worker_pub_key = serialization.load_pem_public_key(
        base64.b64decode(report['public_key'])
    )
    
    encrypted_payload = worker_pub_key.encrypt(
        user_secret.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    print(f"Encrypted Blob: {base64.b64encode(encrypted_payload).decode()[:20]}...")

    # 4. Worker processes in TEE
    # The network only sees the encrypted blob!
    result = worker.process_secure_task(encrypted_payload)
    
    print(f"\n>>> USER: Received Result: {result}")
    print("\n--- PRIVACY PRESERVED ---")

if __name__ == "__main__":
    run_phase3_simulation()
