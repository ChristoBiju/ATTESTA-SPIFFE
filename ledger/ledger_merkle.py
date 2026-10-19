import json

from attestation_ledger import get_attestations
from merkle_tree import (
    hash_leaf,
    build_merkle_tree,
    get_merkle_root,
    generate_proof,
    verify_proof
)


def build_ledger_merkle_tree():
    """
    Build a Merkle tree from the current SQLite ledger.

    Returns the records, tree levels, and Merkle root.
    """

    records = get_attestations()

    if not records:
        raise ValueError("Cannot build a tree from an empty ledger")

    # Use each record's stored hash as the leaf data.
    leaves = [
        hash_leaf(record["record_hash"])
        for record in records
    ]

    levels = build_merkle_tree(leaves)
    root = get_merkle_root(levels)

    return records, levels, root


def generate_attestation_proof(attestation_id):
    """Generate an inclusion proof for a specific attestation."""

    records, levels, root = build_ledger_merkle_tree()

    for index, record in enumerate(records):
        if record["attestation_id"] == attestation_id:
            return {
                "attestation_id": attestation_id,
                "record_hash": record["record_hash"],
                "leaf_hash": levels[0][index],
                "leaf_index": index,
                "merkle_root": root,
                "proof": generate_proof(levels, index)
            }

    raise ValueError("Attestation ID not found")


def verify_attestation_proof(proof_data):
    """Verify a generated proof against its supplied Merkle root."""

    return verify_proof(
        proof_data["leaf_hash"],
        proof_data["proof"],
        proof_data["merkle_root"]
    )


if __name__ == "__main__":
    records, levels, root = build_ledger_merkle_tree()

    print("ATTESTA Ledger Merkle Tree")
    print("--------------------------")
    print("Records included:", len(records))
    print("Merkle root:", root)

    first_record = records[0]

    proof_data = generate_attestation_proof(
        first_record["attestation_id"]
    )

    print("\nInclusion proof:")
    print(json.dumps(proof_data, indent=2))

    print("\nProof valid:", verify_attestation_proof(proof_data))
