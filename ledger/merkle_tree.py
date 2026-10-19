import hashlib


def hash_leaf(data):
    """Hash a leaf with a prefix distinguishing it from internal nodes."""
    if isinstance(data, str):
        data = data.encode("utf-8")

    return hashlib.sha256(b"\x00" + data).hexdigest()


def hash_pair(left, right):
    """Hash two child nodes with a distinct internal-node prefix."""
    left_bytes = bytes.fromhex(left)
    right_bytes = bytes.fromhex(right)

    return hashlib.sha256(
        b"\x01" + left_bytes + right_bytes
    ).hexdigest()


def build_merkle_tree(leaves):
    """
    Build a Merkle tree from leaf hashes.

    An odd final node is duplicated at each level.
    The input leaves must be 64-character SHA-256 hex digests.
    """

    if not leaves:
        raise ValueError("Cannot build a Merkle tree without leaves")

    for leaf in leaves:
        if len(leaf) != 64:
            raise ValueError("Each leaf must be a SHA-256 hex digest")

        try:
            bytes.fromhex(leaf)
        except ValueError as exc:
            raise ValueError("Leaf contains invalid hexadecimal data") from exc

    levels = [list(leaves)]

    while len(levels[-1]) > 1:
        current = levels[-1]
        next_level = []

        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else left

            next_level.append(hash_pair(left, right))

        levels.append(next_level)

    return levels


def get_merkle_root(levels):
    """Return the root of a non-empty Merkle tree."""
    if not levels or not levels[0]:
        raise ValueError("Merkle tree is empty")

    return levels[-1][0]


def generate_proof(levels, index):
    """Generate a Merkle inclusion proof for a leaf index."""

    if not levels or not levels[0]:
        raise ValueError("Merkle tree is empty")

    if not 0 <= index < len(levels[0]):
        raise IndexError("Leaf index is out of range")

    proof = []
    current_index = index

    for level in levels[:-1]:
        if current_index % 2 == 0:
            sibling_index = current_index + 1
            position = "right"
        else:
            sibling_index = current_index - 1
            position = "left"

        if sibling_index >= len(level):
            sibling_index = current_index

        proof.append({
            "hash": level[sibling_index],
            "position": position
        })

        current_index //= 2

    return proof


def verify_proof(leaf_hash, proof, expected_root):
    """Verify a proof using a supplied leaf hash and expected root."""

    try:
        if len(leaf_hash) != 64 or len(expected_root) != 64:
            return False

        bytes.fromhex(leaf_hash)
        bytes.fromhex(expected_root)

        current_hash = leaf_hash

        for item in proof:
            sibling_hash = item["hash"]

            if len(sibling_hash) != 64:
                return False

            bytes.fromhex(sibling_hash)

            if item["position"] == "left":
                current_hash = hash_pair(sibling_hash, current_hash)
            elif item["position"] == "right":
                current_hash = hash_pair(current_hash, sibling_hash)
            else:
                return False

        return current_hash == expected_root

    except (ValueError, TypeError, KeyError):
        return False
