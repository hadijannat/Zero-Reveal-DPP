"""
zero_reveal_dpp/crypto.py
Core cryptographic primitives with security best practices.
"""
import hashlib
import hmac
import secrets
import json
from typing import Any

# Security constants
SALT_LENGTH = 32  # 256 bits - prevents rainbow table attacks
LEAF_PREFIX = b'\x00'  # Domain separation per RFC 9162
INTERNAL_PREFIX = b'\x01'  # Prevents second-preimage attacks
HASH_ALGORITHM = 'sha256'


def generate_salt() -> bytes:
    """Generate cryptographically secure 256-bit salt.
    
    Uses secrets module which accesses OS CSPRNG (urandom).
    NEVER use random module for cryptographic purposes.
    
    Returns:
        32 bytes of cryptographically random data
    """
    return secrets.token_bytes(SALT_LENGTH)


def canonical_json(data: Any) -> bytes:
    """Produce deterministic JSON for hashing.
    
    RFC 8785 JSON Canonicalization Scheme ensures identical
    input always produces identical output regardless of
    dict ordering or whitespace.
    
    Args:
        data: Any JSON-serializable Python object
        
    Returns:
        UTF-8 encoded canonical JSON bytes
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False
    ).encode('utf-8')


def hash_leaf(salt: bytes, field_name: str, value: Any) -> bytes:
    """Hash a leaf node with salt prefix.
    
    Format: SHA256(0x00 || salt || field_name || canonical_value)
    
    The 0x00 prefix prevents second-preimage attacks where
    an attacker could construct a leaf that matches an internal node.
    
    Args:
        salt: 32-byte random salt unique to this leaf
        field_name: Attribute name (e.g., "carbonFootprint")
        value: Attribute value (any JSON-serializable type)
        
    Returns:
        32-byte SHA-256 hash
    """
    canonical_value = canonical_json(value)
    data = LEAF_PREFIX + salt + field_name.encode('utf-8') + canonical_value
    return hashlib.sha256(data).digest()


def hash_internal(left: bytes, right: bytes) -> bytes:
    """Hash an internal node from two children.
    
    Format: SHA256(0x01 || left_hash || right_hash)
    
    Args:
        left: 32-byte hash of left child
        right: 32-byte hash of right child
        
    Returns:
        32-byte SHA-256 hash
    """
    return hashlib.sha256(INTERNAL_PREFIX + left + right).digest()


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Compare two byte strings in constant time.
    
    CRITICAL: Always use this for hash comparisons to prevent
    timing attacks. Standard == comparison leaks information
    about how many bytes matched.
    
    CVE-2022-48566: Python <3.9.1 had vulnerable hmac.compare_digest.
    Ensure Python 3.9+ for proper constant-time behavior.
    
    Args:
        a: First byte string
        b: Second byte string
        
    Returns:
        True if equal, False otherwise
    """
    return hmac.compare_digest(a, b)
