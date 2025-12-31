"""
Zero-Reveal-DPP: Privacy-Preserving Digital Product Passports with Salted Merkle Trees.

This library implements selective disclosure for EU-regulated Digital Product Passports,
enabling manufacturers to prove regulatory compliance without revealing trade secrets.
"""

from .crypto import (
    generate_salt,
    canonical_json,
    hash_leaf,
    hash_internal,
    constant_time_compare,
    SALT_LENGTH,
)

from .merkle import (
    MerkleLeaf,
    MerkleProof,
    SaltedMerkleTree,
)

from .tiers import (
    DisclosureTier,
    EU_BATTERY_TIER_MAPPING,
    TierProofBundle,
    TieredDisclosure,
)

from .qr import (
    PassportQRData,
    generate_passport_qr,
    parse_passport_qr,
)

from .verify import (
    VerificationResult,
    verify_offline,
    create_verification_bundle,
)

__version__ = "0.1.0"

__all__ = [
    # Crypto
    "generate_salt",
    "canonical_json",
    "hash_leaf",
    "hash_internal",
    "constant_time_compare",
    "SALT_LENGTH",
    # Merkle
    "MerkleLeaf",
    "MerkleProof",
    "SaltedMerkleTree",
    # Tiers
    "DisclosureTier",
    "EU_BATTERY_TIER_MAPPING",
    "TierProofBundle",
    "TieredDisclosure",
    # QR
    "PassportQRData",
    "generate_passport_qr",
    "parse_passport_qr",
    # Verify
    "VerificationResult",
    "verify_offline",
    "create_verification_bundle",
    # Meta
    "__version__",
]
