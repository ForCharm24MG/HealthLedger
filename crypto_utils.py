"""
crypto_utils.py
Cryptographic Engine for Healthcare Data Sharing System (HealthLedger).
Implements:
1. Symmetric Authenticated Encryption: AES-256-GCM with 96-bit CSPRNG nonces (NIST SP 800-38D).
2. Asymmetric Key Encapsulation: RSA-2048 with OAEP (SHA-256, MGF1) for recipient session keys.
3. Digital Signatures: RSA-2048 with PSS padding and SHA-256 for non-repudiable blockchain transactions.
4. User Authentication: PBKDF2-HMAC-SHA256 password hashing with 16-byte cryptographically secure salt.
5. Content Addressing: SHA-256 cryptographic digest calculation.
"""

import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# =====================================================================
# 1. User Password Hashing (PBKDF2-HMAC-SHA256)
# =====================================================================

import hmac

PBKDF2_ITERATIONS = 100_000

def hash_password(password: str, salt: bytes = None):
    """
    Hashes a password using PBKDF2-HMAC-SHA256 with a 16-byte random salt.
    Returns: (salt_hex, hash_hex)
    """
    if salt is None:
        salt = os.urandom(16)
    pwd_bytes = password.encode('utf-8')
    derived = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt, PBKDF2_ITERATIONS)
    return salt.hex(), derived.hex()

def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    """
    Verifies a plain password against the stored salt and hash in constant time.
    """
    try:
        salt = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(hash_hex)
        pwd_bytes = password.encode('utf-8')
        derived = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt, PBKDF2_ITERATIONS)
        return hmac.compare_digest(derived, expected_hash)
    except Exception:
        return False

# =====================================================================
# 2. Symmetric Authenticated Encryption (AES-256-GCM)
# =====================================================================

def generate_aes_key() -> bytes:
    """Generate a random 256-bit AES key using CSPRNG."""
    return AESGCM.generate_key(bit_length=256)

def encrypt_bytes(data_bytes: bytes, key: bytes):
    """
    Encrypts raw bytes using AES-256-GCM with a fresh 96-bit CSPRNG nonce.
    Appends the 128-bit authentication tag automatically.
    Returns: (ciphertext_hex, nonce_hex)
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # Standard 96-bit nonce
    ciphertext = aesgcm.encrypt(nonce, data_bytes, None)
    return ciphertext.hex(), nonce.hex()

def decrypt_bytes(ciphertext_hex: str, nonce_hex: str, key: bytes) -> bytes:
    """
    Decrypts AES-256-GCM ciphertext and validates the 128-bit authentication tag.
    Raises InvalidTag exception if ciphertext or nonce was tampered with.
    Returns: decrypted raw bytes
    """
    aesgcm = AESGCM(key)
    ciphertext = bytes.fromhex(ciphertext_hex)
    nonce = bytes.fromhex(nonce_hex)
    return aesgcm.decrypt(nonce, ciphertext, None)

def encrypt_record(plain_text: str, key: bytes):
    """Convenience wrapper for text strings."""
    return encrypt_bytes(plain_text.encode('utf-8'), key)

def decrypt_record(ciphertext_hex: str, nonce_hex: str, key: bytes) -> str:
    """Convenience wrapper for text strings."""
    return decrypt_bytes(ciphertext_hex, nonce_hex, key).decode('utf-8')

# =====================================================================
# 3. Asymmetric Key Encapsulation (RSA-2048 OAEP)
# =====================================================================

def generate_rsa_keypair():
    """Generates a 2048-bit RSA keypair with public exponent e=65537."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def export_rsa_private_key(private_key) -> str:
    """Exports RSA private key to PKCS#8 PEM string."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

def load_rsa_private_key(pem_str: str):
    """Loads RSA private key from PEM string."""
    return serialization.load_pem_private_key(
        pem_str.encode('utf-8'),
        password=None
    )

def export_rsa_public_key(public_key) -> str:
    """Exports RSA public key to SubjectPublicKeyInfo PEM string."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

def load_rsa_public_key(pem_str: str):
    """Loads RSA public key from PEM string."""
    return serialization.load_pem_public_key(
        pem_str.encode('utf-8')
    )

def encrypt_key_for_recipient(aes_key: bytes, recipient_public_key) -> str:
    """
    Encapsulates a 256-bit AES key using recipient's RSA public key via OAEP (SHA-256).
    Returns: 512-hex-character ciphertext string.
    """
    encrypted_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key.hex()

def decrypt_key_with_private_key(encrypted_key_hex: str, recipient_private_key) -> bytes:
    """
    Decapsulates the AES key using recipient's RSA private key via OAEP (SHA-256).
    Returns: 32-byte AES key.
    """
    encrypted_key = bytes.fromhex(encrypted_key_hex)
    return recipient_private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# =====================================================================
# 4. Digital Signatures (RSA-PSS with SHA-256)
# =====================================================================

def sign_data(data_bytes: bytes, private_key) -> str:
    """
    Digitally signs arbitrary data bytes using RSA-PSS padding and SHA-256.
    Returns: signature in hex format (512 hex characters for RSA-2048).
    """
    signature = private_key.sign(
        data_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature.hex()

def verify_signature(data_bytes: bytes, signature_hex: str, public_key) -> bool:
    """
    Verifies an RSA-PSS digital signature against data bytes.
    Returns True if valid, False if modified or invalid.
    """
    try:
        signature = bytes.fromhex(signature_hex)
        public_key.verify(
            signature,
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# =====================================================================
# 5. Content Addressing & Hashing (SHA-256)
# =====================================================================

def compute_bytes_hash(data_bytes: bytes) -> str:
    """Computes SHA-256 hex digest for raw bytes."""
    return hashlib.sha256(data_bytes).hexdigest()

def compute_hash(text: str) -> str:
    """Computes SHA-256 hex digest for string text."""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()
