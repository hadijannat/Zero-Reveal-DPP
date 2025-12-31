"""
tests/test_verify.py
Integration tests for verification workflow.
"""
import pytest
import json
from zero_reveal_dpp.merkle import SaltedMerkleTree
from zero_reveal_dpp.qr import PassportQRData, parse_passport_qr
from zero_reveal_dpp.verify import (
    VerificationResult,
    verify_offline,
    create_verification_bundle
)


@pytest.fixture
def sample_passport():
    """Sample battery passport."""
    return {
        "generalProductInformation": {
            "batteryId": "BATT-TEST-001",
            "manufacturerName": "TestCorp"
        },
        "carbonFootprint": {
            "batteryCarbonFootprint": 55.0,
            "carbonFootprintPerformanceClass": "A"
        }
    }


@pytest.fixture
def built_tree(sample_passport):
    """Built Merkle tree from sample passport."""
    return SaltedMerkleTree.from_passport(sample_passport)


@pytest.fixture
def signature():
    """Placeholder signature for testing."""
    return b'\x00' * 64


class TestVerifyOffline:
    """Tests for offline verification."""
    
    def test_valid_proof_verifies(self, built_tree, signature):
        """Valid proof should verify successfully."""
        proof = built_tree.generate_proof("carbonFootprint.batteryCarbonFootprint")
        
        proof_json = json.dumps({
            'field_name': proof.field_name,
            'value': proof.value,
            'salt': proof.salt,
            'path': proof.path
        })
        
        qr_content = json.dumps({
            'r': built_tree.get_root().hex(),
            's': signature.hex(),
            'i': 'did:web:test.example',
            'v': 'TEST-001'
        }, separators=(',', ':'))
        
        result = verify_offline(proof_json, qr_content)
        
        assert result.is_valid is True
        assert result.field_name == "carbonFootprint.batteryCarbonFootprint"
        assert result.value == 55.0
        assert result.error_message == ""
    
    def test_tampered_value_fails(self, built_tree, signature):
        """Tampered value should fail verification."""
        proof = built_tree.generate_proof("carbonFootprint.batteryCarbonFootprint")
        
        proof_json = json.dumps({
            'field_name': proof.field_name,
            'value': 999.0,  # Tampered!
            'salt': proof.salt,
            'path': proof.path
        })
        
        qr_content = json.dumps({
            'r': built_tree.get_root().hex(),
            's': signature.hex(),
            'i': 'did:web:test.example',
            'v': 'TEST-001'
        }, separators=(',', ':'))
        
        result = verify_offline(proof_json, qr_content)
        
        assert result.is_valid is False
        assert "Merkle proof verification failed" in result.error_message
    
    def test_wrong_root_fails(self, built_tree, signature):
        """Wrong root hash should fail verification."""
        proof = built_tree.generate_proof("carbonFootprint.batteryCarbonFootprint")
        
        proof_json = json.dumps({
            'field_name': proof.field_name,
            'value': proof.value,
            'salt': proof.salt,
            'path': proof.path
        })
        
        qr_content = json.dumps({
            'r': 'ff' * 32,  # Wrong root!
            's': signature.hex(),
            'i': 'did:web:test.example',
            'v': 'TEST-001'
        }, separators=(',', ':'))
        
        result = verify_offline(proof_json, qr_content)
        
        assert result.is_valid is False
    
    def test_malformed_json_handled(self, signature):
        """Malformed JSON should be handled gracefully."""
        result = verify_offline(
            "not valid json",
            '{"r":"00","s":"00","i":"did","v":"1"}'
        )
        
        assert result.is_valid is False
        assert result.error_message != ""
    
    def test_missing_fields_handled(self, built_tree, signature):
        """Missing fields should be handled gracefully."""
        result = verify_offline(
            '{"field_name":"test"}',  # Missing value, salt, path
            '{"r":"00","s":"00","i":"did","v":"1"}'
        )
        
        assert result.is_valid is False


class TestCreateVerificationBundle:
    """Tests for verification bundle creation."""
    
    def test_bundle_structure(self, built_tree, signature):
        """Bundle should have correct structure."""
        bundle = create_verification_bundle(
            tree=built_tree,
            fields_to_disclose=["carbonFootprint.batteryCarbonFootprint"],
            signature=signature,
            issuer_did="did:web:test.example",
            passport_version="TEST-001"
        )
        
        assert bundle['version'] == '1.0.0'
        assert bundle['merkle_root'] == built_tree.get_root().hex()
        assert bundle['signature'] == signature.hex()
        assert bundle['issuer_did'] == "did:web:test.example"
        assert bundle['passport_version'] == "TEST-001"
        assert len(bundle['disclosed_proofs']) == 1
    
    def test_multiple_proofs(self, built_tree, signature):
        """Bundle should include multiple proofs."""
        bundle = create_verification_bundle(
            tree=built_tree,
            fields_to_disclose=[
                "carbonFootprint.batteryCarbonFootprint",
                "carbonFootprint.carbonFootprintPerformanceClass"
            ],
            signature=signature,
            issuer_did="did:web:test.example",
            passport_version="TEST-001"
        )
        
        assert len(bundle['disclosed_proofs']) == 2
    
    def test_proof_contents(self, built_tree, signature):
        """Each proof should have required fields."""
        bundle = create_verification_bundle(
            tree=built_tree,
            fields_to_disclose=["carbonFootprint.batteryCarbonFootprint"],
            signature=signature,
            issuer_did="did:web:test.example",
            passport_version="TEST-001"
        )
        
        proof = bundle['disclosed_proofs'][0]
        assert 'field_name' in proof
        assert 'value' in proof
        assert 'salt' in proof
        assert 'path' in proof
    
    def test_bundle_is_json_serializable(self, built_tree, signature):
        """Bundle should be JSON serializable."""
        bundle = create_verification_bundle(
            tree=built_tree,
            fields_to_disclose=["carbonFootprint.batteryCarbonFootprint"],
            signature=signature,
            issuer_did="did:web:test.example",
            passport_version="TEST-001"
        )
        
        json_str = json.dumps(bundle)
        parsed = json.loads(json_str)
        assert parsed == bundle


class TestPassportQRData:
    """Tests for QR data handling."""
    
    def test_parse_qr_content(self):
        """Should parse QR content correctly."""
        qr_content = json.dumps({
            'r': 'ab' * 32,
            's': 'cd' * 32,
            'i': 'did:web:example.com',
            'v': 'BATT-001-v1',
            'sv': '2.0.0'
        }, separators=(',', ':'))
        
        qr_data = parse_passport_qr(qr_content)
        
        assert qr_data.merkle_root == 'ab' * 32
        assert qr_data.signature == 'cd' * 32
        assert qr_data.issuer_did == 'did:web:example.com'
        assert qr_data.passport_version == 'BATT-001-v1'
        assert qr_data.schema_version == '2.0.0'
    
    def test_parse_qr_default_schema_version(self):
        """Should use default schema version if not provided."""
        qr_content = json.dumps({
            'r': 'ab' * 32,
            's': 'cd' * 32,
            'i': 'did:web:example.com',
            'v': 'BATT-001-v1'
        }, separators=(',', ':'))
        
        qr_data = parse_passport_qr(qr_content)
        assert qr_data.schema_version == '1.0.0'


class TestEndToEndWorkflow:
    """End-to-end integration tests."""
    
    def test_complete_workflow(self, sample_passport, signature):
        """Complete workflow should work end-to-end."""
        # Step 1: Build tree
        tree = SaltedMerkleTree.from_passport(sample_passport)
        root = tree.get_root()
        
        # Step 2: Generate proof
        proof = tree.generate_proof("carbonFootprint.batteryCarbonFootprint")
        
        # Step 3: Serialize for transmission
        proof_json = json.dumps({
            'field_name': proof.field_name,
            'value': proof.value,
            'salt': proof.salt,
            'path': proof.path
        })
        
        qr_content = json.dumps({
            'r': root.hex(),
            's': signature.hex(),
            'i': 'did:web:test.example',
            'v': 'TEST-001'
        }, separators=(',', ':'))
        
        # Step 4: Verify offline
        result = verify_offline(proof_json, qr_content)
        
        # Assertions
        assert result.is_valid is True
        assert result.field_name == "carbonFootprint.batteryCarbonFootprint"
        assert result.value == sample_passport["carbonFootprint"]["batteryCarbonFootprint"]
