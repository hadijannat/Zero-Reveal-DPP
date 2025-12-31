"""
examples/complete_workflow.py
End-to-end example: Mint → Sign → Disclose → Verify
"""
import json
import sys
import os

# Add src to path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from zero_reveal_dpp import (
    SaltedMerkleTree,
    TieredDisclosure,
    DisclosureTier,
    PassportQRData,
    create_verification_bundle,
    verify_offline
)

# ============================================================
# STEP 1: MANUFACTURER - Create Battery Passport
# ============================================================

battery_passport = {
    "generalProductInformation": {
        "batteryId": "BATT-2025-EU-001234",
        "manufacturerName": "EuroCell GmbH",
        "manufacturingDate": "2025-03-15",
        "manufacturingPlace": "Berlin, Germany",
        "batteryCategory": "EV",
        "batteryWeight": 450.0,
        "batteryChemistry": "NMC811"
    },
    "carbonFootprint": {
        "batteryCarbonFootprint": 61.5,
        "carbonFootprintPerformanceClass": "B",
        "carbonFootprintStudyUrl": "https://eurocell.example/cf-2025.pdf"
    },
    "materialComposition": {
        "criticalRawMaterials": ["lithium", "cobalt", "nickel"],
        "recycledContentCobalt": 16.0,
        "recycledContentLithium": 6.0,
        "hazardousSubstances": {
            "containsCadmium": False,
            "containsLead": False
        }
    },
    "performanceAndDurability": {
        "ratedCapacity": 75.0,
        "stateOfHealth": 98.5,
        "fullChargeCycles": 142
    },
    "labelsAndCertification": {
        "ceMarking": True,
        "declarationOfConformityUrl": "https://eurocell.example/doc-2025.pdf"
    }
}

# ============================================================
# STEP 2: Build Salted Merkle Tree
# ============================================================

print("=" * 60)
print("ZERO-REVEAL-DPP: Privacy-Preserving Digital Product Passport")
print("=" * 60)
print()

tree = SaltedMerkleTree.from_passport(battery_passport)
root_hash = tree.get_root()

print(f"✓ Merkle Root: {root_hash.hex()}")
print(f"✓ Tree contains {len(tree._leaves)} attributes")

# ============================================================
# STEP 3: Sign Root Hash (Ed25519 recommended)
# ============================================================

# For production, use cryptography library:
# from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
# private_key = Ed25519PrivateKey.generate()
# signature = private_key.sign(root_hash)

# Placeholder for example
signature = b'\x00' * 64  # Replace with real signature
issuer_did = "did:web:eurocell.example"

print(f"✓ Root hash signed (placeholder signature)")
print(f"✓ Issuer DID: {issuer_did}")

# ============================================================
# STEP 4: Generate QR Code for Product
# ============================================================

qr_data = PassportQRData(
    merkle_root=root_hash.hex(),
    signature=signature.hex(),
    issuer_did=issuer_did,
    passport_version="BATT-2025-EU-001234-v1"
)

# Uncomment to generate actual QR code (requires qrcode[pil]):
# from zero_reveal_dpp import generate_passport_qr
# generate_passport_qr(qr_data, "battery_passport_qr.png")
print("✓ QR code data prepared (generation requires qrcode[pil])")

# ============================================================
# STEP 5: REGULATOR - Request Specific Disclosures
# ============================================================

print()
print("-" * 60)
print("REGULATOR DISCLOSURE REQUEST")
print("-" * 60)

# Regulator requests carbon footprint verification
tiered = TieredDisclosure(tree)
public_bundle = tiered.generate_tier_bundle(DisclosureTier.PUBLIC)

print(f"\n✓ PUBLIC tier proofs generated:")
print(f"  - Fields disclosed: {len(public_bundle.fields_disclosed)}")
for field in public_bundle.fields_disclosed:
    print(f"    • {field}")

if public_bundle.fields_not_found:
    print(f"  - Fields not in passport: {len(public_bundle.fields_not_found)}")

# Generate single-attribute proof for regulator
cf_proof = tree.generate_proof("carbonFootprint.batteryCarbonFootprint")
print(f"\n✓ Carbon footprint proof generated:")
print(f"  - Value: {cf_proof.value} kg CO2e/kWh")
print(f"  - Path length: {len(cf_proof.path)} hashes")

# ============================================================
# STEP 6: VERIFIER - Verify Proofs Offline
# ============================================================

print()
print("-" * 60)
print("OFFLINE VERIFICATION")
print("-" * 60)

# Serialize proof for transmission
proof_json = json.dumps({
    'field_name': cf_proof.field_name,
    'value': cf_proof.value,
    'salt': cf_proof.salt,
    'path': cf_proof.path
})

qr_content = json.dumps({
    'r': root_hash.hex(),
    's': signature.hex(),
    'i': issuer_did,
    'v': "BATT-2025-EU-001234-v1"
}, separators=(',', ':'))

result = verify_offline(proof_json, qr_content)

print(f"\n✓ Verification result:")
print(f"  - Valid: {result.is_valid}")
print(f"  - Field: {result.field_name}")
print(f"  - Value: {result.value}")

# ============================================================
# STEP 7: Verify Entire Tier Bundle
# ============================================================

is_bundle_valid = tiered.verify_tier_bundle(public_bundle)
print(f"\n✓ Public tier bundle valid: {is_bundle_valid}")

# ============================================================
# STEP 8: Create Verification Bundle
# ============================================================

bundle = create_verification_bundle(
    tree=tree,
    fields_to_disclose=[
        "carbonFootprint.batteryCarbonFootprint",
        "carbonFootprint.carbonFootprintPerformanceClass",
        "generalProductInformation.batteryId"
    ],
    signature=signature,
    issuer_did=issuer_did,
    passport_version="BATT-2025-EU-001234-v1"
)

print(f"\n✓ Verification bundle created:")
print(f"  - Version: {bundle['version']}")
print(f"  - Proofs included: {len(bundle['disclosed_proofs'])}")

print()
print("=" * 60)
print("COMPLETE WORKFLOW SUCCESSFUL")
print("=" * 60)
