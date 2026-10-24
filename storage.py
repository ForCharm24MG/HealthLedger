"""
storage.py
Simulated Off-Chain / Content-Addressable Storage (CAS) module.
Stores encrypted medical payloads named by their SHA-256 content identifiers (CID).
Guarantees immutability and verifiable tamper-detection.
"""

import os
import hashlib
import json

STORAGE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "offchain_storage")

def init_storage():
    """Ensure the storage directory exists."""
    os.makedirs(STORAGE_DIR, exist_ok=True)

def save_to_storage(ciphertext_hex: str, nonce_hex: str, metadata: dict = None) -> str:
    """
    Saves an encrypted payload to off-chain storage.
    Content Address (CID) is the SHA-256 digest of the serialized payload.
    Returns: content_hash (64 hex characters)
    """
    init_storage()
    
    payload = {
        "ciphertext": ciphertext_hex,
        "nonce": nonce_hex,
        "metadata": metadata or {}
    }
    
    data_str = json.dumps(payload, sort_keys=True)
    content_hash = hashlib.sha256(data_str.encode('utf-8')).hexdigest()
    
    file_path = os.path.join(STORAGE_DIR, f"{content_hash}.json")
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(data_str)
        
    return content_hash

def get_from_storage(content_hash: str) -> dict:
    """
    Retrieves the encrypted payload from off-chain storage by content hash.
    Verifies on-disk integrity before returning.
    Returns: dict with 'ciphertext', 'nonce', and 'metadata'.
    """
    file_path = os.path.join(STORAGE_DIR, f"{content_hash}.json")
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Record with hash {content_hash} not found in storage.")
        
    with open(file_path, "r", encoding="utf-8") as f:
        raw_text = f.read()

    # Re-verify content-address integrity
    calculated_hash = hashlib.sha256(raw_text.encode('utf-8')).hexdigest()
    if calculated_hash != content_hash:
        raise ValueError(f"CAS Storage Tamper Detected! Expected CID {content_hash}, but found {calculated_hash}")
        
    data = json.loads(raw_text)
    return data

def verify_integrity(content_hash: str) -> bool:
    """
    Checks whether the file on disk matches its SHA-256 CID without raising exceptions.
    Returns: True if intact, False if missing or corrupted.
    """
    file_path = os.path.join(STORAGE_DIR, f"{content_hash}.json")
    if not os.path.exists(file_path):
        return False
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            raw_text = f.read()
        calculated_hash = hashlib.sha256(raw_text.encode('utf-8')).hexdigest()
        return calculated_hash == content_hash
    except Exception:
        return False

def clear_storage():
    """Purges all encrypted off-chain storage JSON payloads."""
    init_storage()
    removed = 0
    for fname in os.listdir(STORAGE_DIR):
        if fname.endswith(".json"):
            try:
                os.remove(os.path.join(STORAGE_DIR, fname))
                removed += 1
            except Exception:
                pass
    return removed
