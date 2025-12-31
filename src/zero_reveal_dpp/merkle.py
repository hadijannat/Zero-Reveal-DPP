"""
zero_reveal_dpp/merkle.py
Salted Merkle Tree implementation for selective disclosure.
"""
import math
import json
from dataclasses import dataclass
from typing import Dict, List, Any, Optional

from .crypto import generate_salt, hash_leaf, hash_internal, constant_time_compare


@dataclass
class MerkleLeaf:
    """Represents a leaf node with salt and original data."""
    field_name: str
    value: Any
    salt: bytes
    hash: bytes
    index: int


@dataclass 
class MerkleProof:
    """Proof structure for selective disclosure."""
    field_name: str
    value: Any
    salt: str  # hex-encoded
    path: List[Dict[str, str]]  # [{position: 'left'|'right', hash: hex}]
    leaf_index: int
    tree_size: int


class SaltedMerkleTree:
    """Salted Merkle Tree for privacy-preserving selective disclosure.
    
    This implementation follows these security standards:
    - RFC 9162 domain separation (0x00 for leaves, 0x01 for internal)
    - 256-bit per-leaf salts (NIST SP 800-132 compliant)
    - Balanced tree construction (padded to power of 2)
    - Constant-time comparison for verification
    
    Example:
        tree = SaltedMerkleTree()
        tree.add_leaf("carbonFootprint", 61.5)
        tree.add_leaf("batteryChemistry", "NMC811")
        root = tree.build()
        
        proof = tree.generate_proof("carbonFootprint")
        is_valid = SaltedMerkleTree.verify_proof(proof, root)
    """
    
    def __init__(self):
        self._leaves: List[MerkleLeaf] = []
        self._tree: List[List[bytes]] = []
        self._built: bool = False
        self._field_index: Dict[str, int] = {}
    
    def add_leaf(
        self, 
        field_name: str, 
        value: Any, 
        salt: Optional[bytes] = None
    ) -> int:
        """Add a salted leaf to the tree.
        
        Args:
            field_name: Attribute name for lookup
            value: Attribute value (JSON-serializable)
            salt: Optional pre-generated salt (for deterministic testing)
            
        Returns:
            Index of the leaf in the tree
            
        Raises:
            ValueError: If tree already built or duplicate field_name
        """
        if self._built:
            raise ValueError("Cannot add leaves after tree is built")
        if field_name in self._field_index:
            raise ValueError(f"Duplicate field name: {field_name}")
        
        if salt is None:
            salt = generate_salt()
        
        leaf_hash = hash_leaf(salt, field_name, value)
        index = len(self._leaves)
        
        leaf = MerkleLeaf(
            field_name=field_name,
            value=value,
            salt=salt,
            hash=leaf_hash,
            index=index
        )
        
        self._leaves.append(leaf)
        self._field_index[field_name] = index
        
        return index
    
    def build(self) -> bytes:
        """Build the Merkle tree and return root hash.
        
        Pads to power of 2 for balanced tree structure.
        Uses distinct empty marker for padding (not duplication)
        to prevent CVE-2012-2459 forgery attacks.
        
        Returns:
            32-byte Merkle root hash
            
        Raises:
            ValueError: If no leaves added
        """
        if not self._leaves:
            raise ValueError("Cannot build tree with no leaves")
        
        # Get leaf hashes
        leaf_hashes = [leaf.hash for leaf in self._leaves]
        
        # Pad to power of 2 with distinct empty marker
        original_size = len(leaf_hashes)
        target_size = 1 << math.ceil(math.log2(max(original_size, 2)))
        empty_marker = hash_leaf(b'\x00' * 32, "__EMPTY__", None)
        
        while len(leaf_hashes) < target_size:
            leaf_hashes.append(empty_marker)
        
        # Build tree bottom-up
        self._tree = [leaf_hashes]
        current_level = leaf_hashes
        
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                next_level.append(
                    hash_internal(current_level[i], current_level[i + 1])
                )
            self._tree.append(next_level)
            current_level = next_level
        
        self._built = True
        return self.get_root()
    
    def get_root(self) -> bytes:
        """Get the Merkle root hash.
        
        Returns:
            32-byte root hash
            
        Raises:
            ValueError: If tree not yet built
        """
        if not self._built:
            raise ValueError("Tree not built yet. Call build() first.")
        return self._tree[-1][0]
    
    def generate_proof(self, field_name: str) -> MerkleProof:
        """Generate inclusion proof for a specific attribute.
        
        Args:
            field_name: Name of attribute to prove
            
        Returns:
            MerkleProof containing value, salt, and path
            
        Raises:
            ValueError: If tree not built or field not found
        """
        if not self._built:
            raise ValueError("Tree not built yet. Call build() first.")
        if field_name not in self._field_index:
            raise ValueError(f"Field not found: {field_name}")
        
        leaf = self._leaves[self._field_index[field_name]]
        path = []
        index = leaf.index
        
        for level in self._tree[:-1]:
            if index % 2 == 0:
                sibling_index = index + 1
                position = 'right'
            else:
                sibling_index = index - 1
                position = 'left'
            
            if sibling_index < len(level):
                path.append({
                    'position': position,
                    'hash': level[sibling_index].hex()
                })
            
            index //= 2
        
        return MerkleProof(
            field_name=leaf.field_name,
            value=leaf.value,
            salt=leaf.salt.hex(),
            path=path,
            leaf_index=leaf.index,
            tree_size=len(self._leaves)
        )
    
    @staticmethod
    def verify_proof(proof: MerkleProof, root: bytes) -> bool:
        """Verify a Merkle inclusion proof.
        
        Verification is O(log n) in tree size - one hash per level.
        Uses constant-time comparison to prevent timing attacks.
        
        Args:
            proof: MerkleProof object with value, salt, and path
            root: Expected 32-byte Merkle root
            
        Returns:
            True if proof is valid, False otherwise
        """
        # Reconstruct leaf hash
        salt = bytes.fromhex(proof.salt)
        current_hash = hash_leaf(salt, proof.field_name, proof.value)
        
        # Walk up the tree
        for step in proof.path:
            sibling = bytes.fromhex(step['hash'])
            if step['position'] == 'left':
                current_hash = hash_internal(sibling, current_hash)
            else:
                current_hash = hash_internal(current_hash, sibling)
        
        return constant_time_compare(current_hash, root)
    
    @classmethod
    def from_passport(
        cls, 
        passport: Dict[str, Any],
        flatten: bool = True
    ) -> 'SaltedMerkleTree':
        """Create tree from passport data structure.
        
        Recursively flattens nested dicts using dot notation.
        Example: {"carbon": {"value": 61.5}} becomes "carbon.value": 61.5
        
        Args:
            passport: Passport data dictionary
            flatten: If True, flatten nested structures
            
        Returns:
            Built SaltedMerkleTree instance
        """
        tree = cls()
        
        def add_recursive(data: Dict, prefix: str = ""):
            for key, value in sorted(data.items()):
                full_key = f"{prefix}.{key}" if prefix else key
                if isinstance(value, dict) and flatten:
                    add_recursive(value, full_key)
                else:
                    tree.add_leaf(full_key, value)
        
        add_recursive(passport)
        tree.build()
        return tree
    
    def to_json(self) -> str:
        """Serialize tree metadata for storage.
        
        NOTE: This includes salts. Store securely!
        """
        return json.dumps({
            'root': self.get_root().hex(),
            'leaves': [
                {
                    'field': leaf.field_name,
                    'value': leaf.value,
                    'salt': leaf.salt.hex(),
                    'hash': leaf.hash.hex()
                }
                for leaf in self._leaves
            ]
        }, sort_keys=True, indent=2)
