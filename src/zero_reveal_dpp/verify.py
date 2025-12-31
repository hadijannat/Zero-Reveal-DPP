"""
zero_reveal_dpp/verify.py
Offline verification workflow - no network required.
"""
import json
from dataclasses import dataclass
from typing import Dict, Any, List, Union

from .merkle import SaltedMerkleTree, MerkleProof
from .qr import PassportQRData, parse_passport_qr


@dataclass
class VerificationResult:
    """Result of proof verification."""
    is_valid: bool
    field_name: str
    value: Any
    error_message: str = ""


def _normalize_public_key(cached_public_key: Union[bytes, str]) -> bytes:
    """Normalize a cached public key into raw bytes.

    Accepts raw bytes or a hex-encoded string.
    """
    if isinstance(cached_public_key, bytes):
        return cached_public_key
    if isinstance(cached_public_key, str):
        return bytes.fromhex(cached_public_key)
    raise TypeError("cached_public_key must be bytes or hex string")


def _verify_ed25519_signature(
    message: bytes,
    signature_hex: str,
    public_key_bytes: bytes
) -> bool:
    """Verify an Ed25519 signature over the message bytes.

    Requires the optional cryptography dependency.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception as exc:
        raise ImportError(
            "Install cryptography for signature verification: "
            "pip install \"zero-reveal-dpp[crypto]\""
        ) from exc

    try:
        signature = bytes.fromhex(signature_hex)
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature, message)
        return True
    except Exception:
        return False


def verify_offline(
    proof_json: str,
    qr_content: str,
    cached_public_key: Union[bytes, str] = None
) -> VerificationResult:
    """Verify a selective disclosure proof offline.
    
    This function requires NO network access. The public key
    should be cached from a prior DID resolution. If provided,
    Ed25519 signature verification is attempted.
    
    Args:
        proof_json: JSON-serialized MerkleProof
        qr_content: Raw QR code content with root hash
        cached_public_key: Pre-cached issuer public key (optional)
        
    Returns:
        VerificationResult with validity status
    """
    try:
        # Parse QR data
        qr_data = parse_passport_qr(qr_content)
        root = bytes.fromhex(qr_data.merkle_root)
        
        # Parse proof
        proof_dict = json.loads(proof_json)
        proof = MerkleProof(
            field_name=proof_dict['field_name'],
            value=proof_dict['value'],
            salt=proof_dict['salt'],
            path=proof_dict['path'],
            leaf_index=proof_dict.get('leaf_index', 0),
            tree_size=proof_dict.get('tree_size', 0)
        )
        
        # Verify Merkle proof
        if not SaltedMerkleTree.verify_proof(proof, root):
            return VerificationResult(
                is_valid=False,
                field_name=proof.field_name,
                value=proof.value,
                error_message="Merkle proof verification failed"
            )
        
        # Verify signature if public key provided (Ed25519)
        if cached_public_key is not None:
            try:
                public_key_bytes = _normalize_public_key(cached_public_key)
                signature_valid = _verify_ed25519_signature(
                    root, qr_data.signature, public_key_bytes
                )
            except Exception as e:
                return VerificationResult(
                    is_valid=False,
                    field_name=proof.field_name,
                    value=proof.value,
                    error_message=str(e)
                )

            if not signature_valid:
                return VerificationResult(
                    is_valid=False,
                    field_name=proof.field_name,
                    value=proof.value,
                    error_message="Signature verification failed"
                )
        
        return VerificationResult(
            is_valid=True,
            field_name=proof.field_name,
            value=proof.value
        )
        
    except Exception as e:
        return VerificationResult(
            is_valid=False,
            field_name="",
            value=None,
            error_message=str(e)
        )


def create_verification_bundle(
    tree: SaltedMerkleTree,
    fields_to_disclose: List[str],
    signature: bytes,
    issuer_did: str,
    passport_version: str
) -> Dict[str, Any]:
    """Create a complete verification bundle for sharing.
    
    The bundle contains everything needed for offline verification.
    
    Args:
        tree: Built SaltedMerkleTree
        fields_to_disclose: List of field names to include
        signature: Signature on root hash
        issuer_did: DID URL for issuer
        passport_version: Passport identifier/version
        
    Returns:
        Dict ready for JSON serialization
    """
    proofs = []
    for field in fields_to_disclose:
        proof = tree.generate_proof(field)
        proofs.append({
            'field_name': proof.field_name,
            'value': proof.value,
            'salt': proof.salt,
            'path': proof.path
        })
    
    return {
        'version': '1.0.0',
        'merkle_root': tree.get_root().hex(),
        'signature': signature.hex(),
        'issuer_did': issuer_did,
        'passport_version': passport_version,
        'disclosed_proofs': proofs
    }
