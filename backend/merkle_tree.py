import hashlib
from typing import List, Optional


def sha256(data: str) -> str:
    """Return SHA-256 hex digest of a string."""
    return hashlib.sha256(data.encode()).hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Return SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


class MerkleTree:
    """
    Binary Merkle Tree for efficient file integrity verification.
    
    Usage:
        tree = MerkleTree(["hash1", "hash2", "hash3"])
        root = tree.get_root()
        proof = tree.get_proof(0)
        valid = MerkleTree.verify_proof("hash1", proof, root)
    """

    def __init__(self, leaf_hashes: List[str]):
        if not leaf_hashes:
            raise ValueError("MerkleTree requires at least one leaf hash")
        self.leaves = leaf_hashes[:]
        self.tree: List[List[str]] = []
        self._build()

    def _build(self):
        """Build the Merkle tree bottom-up."""
        self.tree = []
        current_level = self.leaves[:]

        # Duplicate last leaf if odd number of nodes
        if len(current_level) % 2 == 1:
            current_level.append(current_level[-1])

        self.tree.append(current_level[:])

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else current_level[i]
                combined = sha256(left + right)
                next_level.append(combined)
            if len(next_level) % 2 == 1 and len(next_level) > 1:
                next_level.append(next_level[-1])
            current_level = next_level
            self.tree.append(current_level[:])

    def get_root(self) -> str:
        """Return the Merkle root hash."""
        if not self.tree:
            return ""
        return self.tree[-1][0]

    def get_proof(self, leaf_index: int) -> List[dict]:
        """
        Get the Merkle proof (sibling path) for a leaf at given index.
        Returns list of {"hash": ..., "position": "left"|"right"}.
        """
        if leaf_index < 0 or leaf_index >= len(self.leaves):
            raise IndexError("Leaf index out of range")

        proof = []
        index = leaf_index

        for level in self.tree[:-1]:  # all levels except root
            sibling_index = index + 1 if index % 2 == 0 else index - 1
            sibling_index = min(sibling_index, len(level) - 1)
            position = "right" if index % 2 == 0 else "left"
            proof.append({"hash": level[sibling_index], "position": position})
            index = index // 2

        return proof

    @staticmethod
    def verify_proof(leaf_hash: str, proof: List[dict], root: str) -> bool:
        """
        Verify a Merkle proof.
        Returns True if the leaf_hash with the given proof leads to root.
        """
        current = leaf_hash
        for step in proof:
            if step["position"] == "right":
                current = sha256(current + step["hash"])
            else:
                current = sha256(step["hash"] + current)
        return current == root

    def get_tree_structure(self) -> dict:
        """Return tree structure as a dict for JSON serialization."""
        return {
            "leaves": self.leaves,
            "levels": self.tree,
            "root": self.get_root(),
            "depth": len(self.tree),
            "leaf_count": len(self.leaves),
        }


def hash_file(file_bytes: bytes) -> str:
    """Hash raw file bytes using SHA-256."""
    return sha256_bytes(file_bytes)


def build_merkle_from_files(file_hashes: List[str]) -> MerkleTree:
    """Build a Merkle tree from a list of file hashes."""
    return MerkleTree(file_hashes)
