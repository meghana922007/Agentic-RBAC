import hashlib
import time
import os
import json

def simulate_ipfs_upload(content: str, filename: str) -> str:
    """
    Mocks an IPFS upload. 
    Generates a SHA-256 hash of the content, mimics a CID,
    and simulates a real IPFS Content Identifier.
    """
    # 1. Compute SHA-256
    hash_hex = hashlib.sha256(content.encode('utf-8')).hexdigest()
    
    # 2. Mock base58 CID (typically start with Qm and are 46 chars)
    cid = "Qm" + hash_hex[:44]
    
    # 3. Simulate network latency
    time.sleep(1.5)
    
    # 4. Save to mock IPFS storage folder
    ipfs_dir = "ipfs_mock"
    if not os.path.exists(ipfs_dir):
        os.makedirs(ipfs_dir)
        
    ipfs_file = os.path.join(ipfs_dir, f"{cid}.json")
    with open(ipfs_file, "w") as f:
        json.dump({
            "filename": filename,
            "cid": cid,
            "content": content,
            "timestamp": time.time()
        }, f, indent=4)
    
    return cid
