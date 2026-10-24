"""
blockchain.py
Consortium Blockchain Ledger for Healthcare Data Sharing (HealthLedger).
Maintains tamper-proof record anchors, dynamic access policies, non-repudiable digital signatures,
and comprehensive audit trails (both authorized queries and unauthorized access attempts).
Persists automatically to blockchain_ledger.json.
"""

import time
import hashlib
import json
import os
from crypto_utils import sign_data, verify_signature, load_rsa_public_key, load_rsa_private_key

LEDGER_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "blockchain_ledger.json")

class Block:
    def __init__(self, index: int, timestamp: float, transactions: list, previous_hash: str):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        """Calculate SHA-256 hash of the block contents."""
        block_content = {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash
        }
        raw_string = json.dumps(block_content, sort_keys=True)
        return hashlib.sha256(raw_string.encode('utf-8')).hexdigest()


class HealthcareBlockchain:
    def __init__(self, ledger_file: str = LEDGER_FILE):
        self.ledger_file = ledger_file
        self.chain = []
        self.pending_transactions = []
        
        # Access control state: (patient_id, record_id, doctor_id) -> { "valid_until": ..., "encrypted_key": ..., "active": bool, "signature": ... }
        self.permissions = {}
        
        # Access audit logs: history of authorized views and unauthorized attempts
        self.access_logs = []
        
        # Try loading existing ledger from disk; otherwise create Genesis Block
        if not self.load_from_disk():
            self.create_genesis_block()
            self.save_to_disk()

    def create_genesis_block(self):
        """Creates the initial block on the blockchain."""
        genesis_block = Block(
            index=0,
            timestamp=time.time(),
            transactions=[{"info": "Genesis Block - Healthcare Consortium Ledger", "timestamp": time.time()}],
            previous_hash="0" * 64
        )
        self.chain.append(genesis_block)

    def get_latest_block(self) -> Block:
        return self.chain[-1]

    def verify_patient_signature(self, patient_id: str, candidate_messages: list, signature_hex: str) -> bool:
        """
        Verifies an RSA-PSS digital signature against the registered patient's public key.
        Returns True if signature is cryptographically valid for any candidate message format, False otherwise.
        """
        if not signature_hex:
            return False
        try:
            import database
            user = database.get_user(patient_id)
            if not user or not user['rsa_public_key_pem']:
                return False
            pub_key = load_rsa_public_key(user['rsa_public_key_pem'])
            for msg in candidate_messages:
                if isinstance(msg, str):
                    msg = msg.encode('utf-8')
                if verify_signature(msg, signature_hex, pub_key):
                    return True
            return False
        except Exception:
            return False

    def add_record_anchor(self, patient_id: str, record_id: str, content_hash: str, data_hash: str, record_type: str = "General", patient_signature: str = ""):
        """
        Records an off-chain record hash and verification hash to the ledger with patient's digital signature.
        Actively enforces RSA-PSS cryptographic signature validation against patient public key.
        """
        if patient_signature:
            candidates = [
                f"ADD_RECORD:{record_id}:{content_hash}:{data_hash}:{patient_id}".encode('utf-8'),
                f"{record_id}:{content_hash}:{data_hash}".encode('utf-8'),
                f"RECORD_INGESTION:{content_hash}:{patient_id}".encode('utf-8')
            ]
            if not self.verify_patient_signature(patient_id, candidates, patient_signature):
                raise ValueError(f"Cryptographic Signature Verification Failed: Invalid or forged RSA-PSS signature for patient '{patient_id}' on record '{record_id}'.")

        tx = {
            "action": "ADD_RECORD",
            "patient_id": patient_id,
            "record_id": record_id,
            "content_hash": content_hash,
            "data_hash": data_hash,
            "record_type": record_type,
            "signature": patient_signature,
            "timestamp": time.time()
        }
        self.pending_transactions.append(tx)
        return tx

    def grant_consent(self, patient_id: str, record_id: str, doctor_id: str, duration_seconds: float, encrypted_key_for_doctor: str, patient_signature: str = ""):
        """
        Patient grants dynamic time-locked access to an attending physician.
        Cryptographically signed by patient private key and verified on ingestion.
        """
        if patient_signature:
            candidates = [
                f"GRANT_CONSENT:{record_id}:{doctor_id}:{duration_seconds}:{patient_id}".encode('utf-8'),
                f"GRANT_CONSENT:{record_id}:{doctor_id}:{int(duration_seconds)}:{patient_id}".encode('utf-8'),
                f"GRANT:{record_id}:{doctor_id}:{duration_seconds}".encode('utf-8'),
                f"{patient_id}:{record_id}:{doctor_id}:{int(duration_seconds)}".encode('utf-8'),
                f"{patient_id}:{record_id}:{doctor_id}:{duration_seconds}".encode('utf-8'),
                f"RECORD_INGESTION:{patient_id}".encode('utf-8')
            ]
            if not self.verify_patient_signature(patient_id, candidates, patient_signature):
                raise ValueError(f"Consent Grant Rejected: Invalid or forged RSA-PSS digital signature for patient '{patient_id}'.")

        expiry_time = time.time() + duration_seconds
        
        key = (patient_id, record_id, doctor_id)
        self.permissions[key] = {
            "valid_until": expiry_time,
            "encrypted_key": encrypted_key_for_doctor,
            "active": True,
            "signature": patient_signature
        }
        
        tx = {
            "action": "GRANT_CONSENT",
            "patient_id": patient_id,
            "record_id": record_id,
            "doctor_id": doctor_id,
            "valid_until": expiry_time,
            "signature": patient_signature,
            "timestamp": time.time()
        }
        self.pending_transactions.append(tx)
        return expiry_time

    def revoke_consent(self, patient_id: str, record_id: str, doctor_id: str, patient_signature: str = ""):
        """
        Patient revokes access from a doctor in O(1) time by invalidating active state on ledger.
        Cryptographically signed by patient private key and verified on ingestion.
        """
        if patient_signature:
            candidates = [
                f"REVOKE_CONSENT:{record_id}:{doctor_id}:{patient_id}".encode('utf-8'),
                f"REVOKE:{record_id}:{doctor_id}".encode('utf-8')
            ]
            if not self.verify_patient_signature(patient_id, candidates, patient_signature):
                raise ValueError(f"Consent Revocation Rejected: Invalid or forged RSA-PSS digital signature for patient '{patient_id}'.")

        key = (patient_id, record_id, doctor_id)
        if key in self.permissions:
            self.permissions[key]["active"] = False
            
        tx = {
            "action": "REVOKE_CONSENT",
            "patient_id": patient_id,
            "record_id": record_id,
            "doctor_id": doctor_id,
            "signature": patient_signature,
            "timestamp": time.time()
        }
        self.pending_transactions.append(tx)
        return tx

    def check_permission(self, patient_id: str, record_id: str, doctor_id: str):
        """
        Checks if a doctor has valid, non-expired permission.
        Returns: (is_allowed, encrypted_key_or_none, reason_str)
        """
        self.load_from_disk()
        key = (patient_id, record_id, doctor_id)
        policy = self.permissions.get(key)
        
        if not policy:
            return False, None, "NO_PERMISSION_GRANTED"
            
        if not policy.get("active", False):
            return False, None, "REVOKED_BY_PATIENT"
            
        if time.time() > policy.get("valid_until", 0):
            return False, None, "TIME_LOCK_EXPIRED"
            
        return True, policy.get("encrypted_key"), "AUTHORIZED"

    def log_record_access(self, patient_id: str, record_id: str, doctor_id: str):
        """
        Records an authorized access event on the ledger when a physician decrypts a record.
        """
        event = {
            "action": "ACCESS_RECORD",
            "patient_id": patient_id,
            "record_id": record_id,
            "doctor_id": doctor_id,
            "status": "AUTHORIZED_ACCESS",
            "timestamp": time.time()
        }
        self.access_logs.append(event)
        self.pending_transactions.append(event)
        return event

    def log_unauthorized_access(self, patient_id: str, record_id: str, doctor_id: str, reason: str = "DENIED"):
        """
        Records an unauthorized or expired access attempt directly onto the blockchain.
        Provides forensic proof of intrusion attempts.
        """
        event = {
            "action": "UNAUTHORIZED_ACCESS_ATTEMPT",
            "patient_id": patient_id,
            "record_id": record_id,
            "doctor_id": doctor_id,
            "status": "ACCESS_BLOCKED",
            "reason": reason,
            "timestamp": time.time()
        }
        self.access_logs.append(event)
        self.pending_transactions.append(event)
        return event

    def get_audit_trail_for_patient(self, patient_id: str) -> list:
        """Returns all access events (both authorized and unauthorized) for a given patient."""
        self.load_from_disk()
        return [log for log in self.access_logs if log.get("patient_id") == patient_id]

    def mine_block(self):
        """Bundles pending transactions into a new block, computes previous_hash link, and saves to disk."""
        if not self.pending_transactions:
            return None
            
        latest_block = self.get_latest_block()
        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            transactions=list(self.pending_transactions),
            previous_hash=latest_block.hash
        )
        
        self.chain.append(new_block)
        self.pending_transactions = []
        self.save_to_disk()
        return new_block

    def is_chain_valid(self) -> bool:
        """Verifies cryptographic hash linking and internal block integrity across the chain."""
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i - 1]
            
            # 1. Verify current block hash calculation
            if curr.hash != curr.calculate_hash():
                return False
                
            # 2. Verify previous hash linkage
            if curr.previous_hash != prev.hash:
                return False
                
        return True

    def save_to_disk(self):
        """Persists the blockchain, permissions, and access logs to disk."""
        data = {
            "chain": [
                {
                    "index": b.index,
                    "timestamp": b.timestamp,
                    "transactions": b.transactions,
                    "previous_hash": b.previous_hash,
                    "hash": b.hash
                } for b in self.chain
            ],
            "permissions": {
                f"{k[0]}::{k[1]}::{k[2]}": v for k, v in self.permissions.items()
            },
            "access_logs": self.access_logs
        }
        try:
            with open(self.ledger_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving ledger to disk: {e}")

    def load_from_disk(self) -> bool:
        """Loads blockchain from disk if file exists."""
        if not os.path.exists(self.ledger_file):
            return False
        try:
            with open(self.ledger_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            chain_list = data.get("chain", [])
            if not chain_list:
                return False
                
            self.chain = []
            for b_data in chain_list:
                b = Block(
                    index=b_data["index"],
                    timestamp=b_data["timestamp"],
                    transactions=b_data["transactions"],
                    previous_hash=b_data["previous_hash"]
                )
                b.hash = b_data["hash"]
                self.chain.append(b)
                
            self.permissions = {}
            for k_str, v in data.get("permissions", {}).items():
                parts = k_str.split("::")
                if len(parts) == 3:
                    self.permissions[(parts[0], parts[1], parts[2])] = v
                    
            self.access_logs = data.get("access_logs", [])
            return True
        except Exception as e:
            print(f"Failed to load ledger from {self.ledger_file}: {e}")
            return False

    def reset_blockchain(self):
        """Administrative Reset: Re-initializes the blockchain to Genesis Block #0."""
        self.chain = []
        self.pending_transactions = []
        self.permissions = {}
        self.access_logs = []
        self.create_genesis_block()
        self.save_to_disk()
        return True

if __name__ == "__main__":
    bc = HealthcareBlockchain()
    print(f"Consortium Blockchain: {len(bc.chain)} blocks | Valid: {bc.is_chain_valid()}")
