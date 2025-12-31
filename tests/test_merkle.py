"""
tests/test_merkle.py
Unit tests for Salted Merkle Tree implementation.
"""
import pytest
import json
from zero_reveal_dpp.merkle import SaltedMerkleTree, MerkleLeaf, MerkleProof
from zero_reveal_dpp.crypto import generate_salt


class TestSaltedMerkleTreeBasic:
    """Basic tree construction tests."""
    
    def test_add_single_leaf(self):
        """Tree should accept a single leaf."""
        tree = SaltedMerkleTree()
        index = tree.add_leaf("field", "value")
        assert index == 0
        assert len(tree._leaves) == 1
    
    def test_add_multiple_leaves(self):
        """Tree should accept multiple leaves."""
        tree = SaltedMerkleTree()
        tree.add_leaf("field1", "value1")
        tree.add_leaf("field2", "value2")
        tree.add_leaf("field3", "value3")
        assert len(tree._leaves) == 3
    
    def test_duplicate_field_rejected(self):
        """Duplicate field names should raise error."""
        tree = SaltedMerkleTree()
        tree.add_leaf("field", "value1")
        with pytest.raises(ValueError, match="Duplicate field name"):
            tree.add_leaf("field", "value2")
    
    def test_add_after_build_rejected(self):
        """Adding leaves after build should raise error."""
        tree = SaltedMerkleTree()
        tree.add_leaf("field", "value")
        tree.build()
        with pytest.raises(ValueError, match="Cannot add leaves after tree is built"):
            tree.add_leaf("field2", "value2")
    
    def test_build_empty_tree_rejected(self):
        """Building empty tree should raise error."""
        tree = SaltedMerkleTree()
        with pytest.raises(ValueError, match="Cannot build tree with no leaves"):
            tree.build()


class TestSaltedMerkleTreeBuild:
    """Tree building tests."""
    
    def test_build_returns_root(self):
        """Build should return 32-byte root hash."""
        tree = SaltedMerkleTree()
        tree.add_leaf("field", "value")
        root = tree.build()
        assert len(root) == 32
        assert isinstance(root, bytes)
    
    def test_get_root_before_build_rejected(self):
        """Getting root before build should raise error."""
        tree = SaltedMerkleTree()
        tree.add_leaf("field", "value")
        with pytest.raises(ValueError, match="Tree not built yet"):
            tree.get_root()
    
    def test_deterministic_build(self):
        """Same inputs with same salts should produce same root."""
        salt = b'\x00' * 32
        
        tree1 = SaltedMerkleTree()
        tree1.add_leaf("field", "value", salt=salt)
        root1 = tree1.build()
        
        tree2 = SaltedMerkleTree()
        tree2.add_leaf("field", "value", salt=salt)
        root2 = tree2.build()
        
        assert root1 == root2
    
    def test_different_salts_different_roots(self):
        """Different salts should produce different roots."""
        tree1 = SaltedMerkleTree()
        tree1.add_leaf("field", "value", salt=b'\x00' * 32)
        root1 = tree1.build()
        
        tree2 = SaltedMerkleTree()
        tree2.add_leaf("field", "value", salt=b'\x01' * 32)
        root2 = tree2.build()
        
        assert root1 != root2
    
    def test_padding_to_power_of_two(self):
        """Tree should pad to power of 2."""
        tree = SaltedMerkleTree()
        for i in range(3):  # 3 leaves -> pads to 4
            tree.add_leaf(f"field{i}", f"value{i}")
        tree.build()
        
        # First level should have 4 elements
        assert len(tree._tree[0]) == 4


class TestProofGeneration:
    """Proof generation tests."""
    
    def test_generate_proof_structure(self):
        """Proof should have correct structure."""
        tree = SaltedMerkleTree()
        tree.add_leaf("field1", "value1")
        tree.add_leaf("field2", "value2")
        tree.build()
        
        proof = tree.generate_proof("field1")
        
        assert isinstance(proof, MerkleProof)
        assert proof.field_name == "field1"
        assert proof.value == "value1"
        assert isinstance(proof.salt, str)  # hex-encoded
        assert isinstance(proof.path, list)
    
    def test_generate_proof_not_found(self):
        """Proof for non-existent field should raise error."""
        tree = SaltedMerkleTree()
        tree.add_leaf("field1", "value1")
        tree.build()
        
        with pytest.raises(ValueError, match="Field not found"):
            tree.generate_proof("nonexistent")
    
    def test_generate_proof_before_build(self):
        """Generating proof before build should raise error."""
        tree = SaltedMerkleTree()
        tree.add_leaf("field", "value")
        
        with pytest.raises(ValueError, match="Tree not built yet"):
            tree.generate_proof("field")
    
    def test_proof_path_length(self):
        """Proof path length should be log2(tree_size)."""
        tree = SaltedMerkleTree()
        for i in range(8):  # 8 leaves -> 3 levels
            tree.add_leaf(f"field{i}", f"value{i}")
        tree.build()
        
        proof = tree.generate_proof("field0")
        assert len(proof.path) == 3  # log2(8) = 3


class TestProofVerification:
    """Proof verification tests."""
    
    def test_valid_proof_verifies(self):
        """Valid proof should verify successfully."""
        tree = SaltedMerkleTree()
        tree.add_leaf("field1", "value1")
        tree.add_leaf("field2", "value2")
        tree.build()
        
        proof = tree.generate_proof("field1")
        root = tree.get_root()
        
        assert SaltedMerkleTree.verify_proof(proof, root) is True
    
    def test_tampered_value_fails(self):
        """Proof with tampered value should fail."""
        tree = SaltedMerkleTree()
        tree.add_leaf("field1", "value1")
        tree.build()
        
        proof = tree.generate_proof("field1")
        proof.value = "tampered"  # Tamper with value
        root = tree.get_root()
        
        assert SaltedMerkleTree.verify_proof(proof, root) is False
    
    def test_tampered_salt_fails(self):
        """Proof with tampered salt should fail."""
        tree = SaltedMerkleTree()
        tree.add_leaf("field1", "value1")
        tree.build()
        
        proof = tree.generate_proof("field1")
        proof.salt = "00" * 32  # Tamper with salt
        root = tree.get_root()
        
        assert SaltedMerkleTree.verify_proof(proof, root) is False
    
    def test_wrong_root_fails(self):
        """Proof against wrong root should fail."""
        tree = SaltedMerkleTree()
        tree.add_leaf("field1", "value1")
        tree.build()
        
        proof = tree.generate_proof("field1")
        wrong_root = b'\xff' * 32
        
        assert SaltedMerkleTree.verify_proof(proof, wrong_root) is False
    
    def test_all_leaves_verify(self):
        """All leaves in tree should produce valid proofs."""
        tree = SaltedMerkleTree()
        for i in range(10):
            tree.add_leaf(f"field{i}", f"value{i}")
        tree.build()
        
        root = tree.get_root()
        for i in range(10):
            proof = tree.generate_proof(f"field{i}")
            assert SaltedMerkleTree.verify_proof(proof, root) is True


class TestFromPassport:
    """Tests for passport factory method."""
    
    def test_simple_passport(self):
        """Simple passport should create valid tree."""
        passport = {
            "id": "BATT-001",
            "manufacturer": "TestCorp"
        }
        
        tree = SaltedMerkleTree.from_passport(passport)
        assert len(tree._leaves) == 2
        assert tree._built is True
    
    def test_nested_passport(self):
        """Nested passport should be flattened."""
        passport = {
            "general": {
                "id": "BATT-001",
                "name": "Battery"
            }
        }
        
        tree = SaltedMerkleTree.from_passport(passport)
        
        # Should have flattened keys
        proof = tree.generate_proof("general.id")
        assert proof.value == "BATT-001"
    
    def test_deeply_nested_passport(self):
        """Deeply nested passport should be fully flattened."""
        passport = {
            "level1": {
                "level2": {
                    "level3": "deep_value"
                }
            }
        }
        
        tree = SaltedMerkleTree.from_passport(passport)
        proof = tree.generate_proof("level1.level2.level3")
        assert proof.value == "deep_value"
    
    def test_various_value_types(self):
        """Passport with various types should work."""
        passport = {
            "string": "text",
            "number": 42,
            "float": 3.14,
            "bool": True,
            "null": None,
            "array": [1, 2, 3]
        }
        
        tree = SaltedMerkleTree.from_passport(passport)
        assert len(tree._leaves) == 6
        
        # Verify each type
        proof = tree.generate_proof("array")
        assert proof.value == [1, 2, 3]


class TestToJson:
    """Tests for JSON serialization."""
    
    def test_to_json_structure(self):
        """Serialized JSON should have correct structure."""
        tree = SaltedMerkleTree()
        tree.add_leaf("field", "value")
        tree.build()
        
        json_str = tree.to_json()
        data = json.loads(json_str)
        
        assert "root" in data
        assert "leaves" in data
        assert len(data["leaves"]) == 1
        assert data["leaves"][0]["field"] == "field"
        assert data["leaves"][0]["value"] == "value"
        assert "salt" in data["leaves"][0]
        assert "hash" in data["leaves"][0]
