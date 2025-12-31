# Zero-Reveal-DPP

**Privacy-Preserving Digital Product Passports with Salted Merkle Trees**

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-green)](LICENSE)
[![EU Battery Regulation](https://img.shields.io/badge/EU%20Battery%20Reg-2023%2F1542%20Aligned-gold)](#)

Selective disclosure for Digital Product Passports—prove specific attributes without revealing other fields.

## Quick Start

```bash
# Install
pip install -e .

# Run example
python examples/complete_workflow.py
```

Optional extras:

```bash
# QR + signature verification
pip install -e ".[qr,crypto]"
```

## Features

- **Salted Merkle Trees**: 256-bit per-attribute salts mitigate precomputed dictionary attacks
- **Selective Disclosure**: Prove specific attributes without revealing others
- **EU Battery Regulation Aligned**: Three-tier access control (PUBLIC, AUTHORITIES, LEGITIMATE_INTEREST) with a sample Annex XIII field mapping (not legal compliance)
- **Offline Verification**: Merkle proofs verify with just the QR data + proof; optional issuer signature verification requires a cached public key and `cryptography`
- **Zero Dependencies (core)**: Core uses only Python stdlib (hashlib, hmac, secrets, json)
- **QR Codes (optional)**: Generate/parse QR payloads with `qrcode[pil]`

## Usage

```python
from zero_reveal_dpp import SaltedMerkleTree, TieredDisclosure, DisclosureTier

# Create passport and build tree
passport = {
    "carbonFootprint": {"batteryCarbonFootprint": 61.5},
    "generalProductInformation": {"batteryId": "BATT-001"}
}
tree = SaltedMerkleTree.from_passport(passport)

# Generate proof for a single attribute
proof = tree.generate_proof("carbonFootprint.batteryCarbonFootprint")

# Verify proof
is_valid = SaltedMerkleTree.verify_proof(proof, tree.get_root())
print(f"Valid: {is_valid}")  # True

# Generate tier bundle for regulators
tiered = TieredDisclosure(tree)
public_bundle = tiered.generate_tier_bundle(DisclosureTier.PUBLIC)
```

## Project Structure

```
zero-reveal-dpp/
├── src/zero_reveal_dpp/
│   ├── crypto.py    # Cryptographic primitives
│   ├── merkle.py    # Salted Merkle Tree
│   ├── tiers.py     # EU Battery Reg disclosure tiers
│   ├── qr.py        # QR code generation/parsing
│   └── verify.py    # Offline verification workflow
├── examples/
│   └── complete_workflow.py
└── tests/
```

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## License

Apache 2.0 (see LICENSE)
