"""
tests/test_crypto.py
Unit tests for cryptographic primitives.
"""
import pytest
from zero_reveal_dpp.crypto import (
    generate_salt,
    canonical_json,
    hash_leaf,
    hash_internal,
    constant_time_compare,
    SALT_LENGTH,
    LEAF_PREFIX,
    INTERNAL_PREFIX
)


class TestGenerateSalt:
    """Tests for salt generation."""
    
    def test_salt_length(self):
        """Salt should be exactly 32 bytes (256 bits)."""
        salt = generate_salt()
        assert len(salt) == SALT_LENGTH
        assert len(salt) == 32
    
    def test_salt_randomness(self):
        """Each salt should be unique."""
        salts = [generate_salt() for _ in range(100)]
        assert len(set(salts)) == 100
    
    def test_salt_is_bytes(self):
        """Salt should be bytes type."""
        salt = generate_salt()
        assert isinstance(salt, bytes)


class TestCanonicalJson:
    """Tests for canonical JSON serialization."""
    
    def test_deterministic_dict_ordering(self):
        """Dict key order should not affect output."""
        d1 = {"b": 1, "a": 2}
        d2 = {"a": 2, "b": 1}
        assert canonical_json(d1) == canonical_json(d2)
    
    def test_no_whitespace(self):
        """Output should have no unnecessary whitespace."""
        data = {"key": "value", "num": 123}
        result = canonical_json(data)
        assert b' ' not in result
        assert b'\n' not in result
    
    def test_nested_dict(self):
        """Nested dicts should be sorted recursively."""
        data = {"outer": {"z": 1, "a": 2}}
        result = canonical_json(data)
        assert b'{"outer":{"a":2,"z":1}}' == result
    
    def test_unicode_preserved(self):
        """Unicode characters should be preserved."""
        data = {"name": "München"}
        result = canonical_json(data)
        assert "München".encode('utf-8') in result
    
    def test_various_types(self):
        """Various JSON types should serialize correctly."""
        data = {
            "string": "hello",
            "number": 42,
            "float": 3.14,
            "bool": True,
            "null": None,
            "array": [1, 2, 3]
        }
        result = canonical_json(data)
        assert isinstance(result, bytes)


class TestHashLeaf:
    """Tests for leaf hashing."""
    
    def test_deterministic(self):
        """Same inputs should produce same hash."""
        salt = b'\x00' * 32
        h1 = hash_leaf(salt, "field", "value")
        h2 = hash_leaf(salt, "field", "value")
        assert h1 == h2
    
    def test_hash_length(self):
        """Hash should be 32 bytes (SHA-256)."""
        salt = generate_salt()
        h = hash_leaf(salt, "field", 123)
        assert len(h) == 32
    
    def test_salt_changes_hash(self):
        """Different salt should produce different hash."""
        salt1 = b'\x00' * 32
        salt2 = b'\x01' * 32
        h1 = hash_leaf(salt1, "field", "value")
        h2 = hash_leaf(salt2, "field", "value")
        assert h1 != h2
    
    def test_field_name_changes_hash(self):
        """Different field name should produce different hash."""
        salt = b'\x00' * 32
        h1 = hash_leaf(salt, "field1", "value")
        h2 = hash_leaf(salt, "field2", "value")
        assert h1 != h2
    
    def test_value_changes_hash(self):
        """Different value should produce different hash."""
        salt = b'\x00' * 32
        h1 = hash_leaf(salt, "field", "value1")
        h2 = hash_leaf(salt, "field", "value2")
        assert h1 != h2
    
    def test_complex_value(self):
        """Complex values should hash correctly."""
        salt = generate_salt()
        value = {"nested": {"key": [1, 2, 3]}}
        h = hash_leaf(salt, "complex", value)
        assert len(h) == 32


class TestHashInternal:
    """Tests for internal node hashing."""
    
    def test_deterministic(self):
        """Same inputs should produce same hash."""
        left = b'\x00' * 32
        right = b'\x01' * 32
        h1 = hash_internal(left, right)
        h2 = hash_internal(left, right)
        assert h1 == h2
    
    def test_hash_length(self):
        """Hash should be 32 bytes."""
        left = b'\x00' * 32
        right = b'\x01' * 32
        h = hash_internal(left, right)
        assert len(h) == 32
    
    def test_order_matters(self):
        """Swapping left/right should produce different hash."""
        left = b'\x00' * 32
        right = b'\x01' * 32
        h1 = hash_internal(left, right)
        h2 = hash_internal(right, left)
        assert h1 != h2
    
    def test_domain_separation(self):
        """Internal hash should differ from leaf hash."""
        # Create a fake "leaf" that looks like concatenation of two hashes
        salt = b'\x00' * 32
        fake_value = b'\x01' * 32
        
        # This should NOT be equal due to domain separation prefixes
        leaf_hash = hash_leaf(salt, "", fake_value.hex())
        internal_hash = hash_internal(salt, fake_value)
        assert leaf_hash != internal_hash


class TestConstantTimeCompare:
    """Tests for constant-time comparison."""
    
    def test_equal_bytes(self):
        """Equal bytes should return True."""
        a = b'hello world'
        b = b'hello world'
        assert constant_time_compare(a, b) is True
    
    def test_unequal_bytes(self):
        """Unequal bytes should return False."""
        a = b'hello'
        b = b'world'
        assert constant_time_compare(a, b) is False
    
    def test_different_length(self):
        """Different length bytes should return False."""
        a = b'short'
        b = b'longer string'
        assert constant_time_compare(a, b) is False
    
    def test_empty_bytes(self):
        """Empty bytes should be equal."""
        assert constant_time_compare(b'', b'') is True
    
    def test_hash_comparison(self):
        """Should work for SHA-256 hashes."""
        import hashlib
        h1 = hashlib.sha256(b'test').digest()
        h2 = hashlib.sha256(b'test').digest()
        h3 = hashlib.sha256(b'other').digest()
        
        assert constant_time_compare(h1, h2) is True
        assert constant_time_compare(h1, h3) is False
