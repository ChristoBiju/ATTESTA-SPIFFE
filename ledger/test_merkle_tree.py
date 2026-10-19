from merkle_tree import (
    build_merkle_tree,
    get_merkle_root,
    generate_proof,
    verify_proof
)


def run_test():
    # Four sample attestation record hashes
    leaves = [
        "a" * 64,
        "b" * 64,
        "c" * 64,
        "d" * 64
    ]

    # Build the Merkle tree
    levels = build_merkle_tree(leaves)
    root = get_merkle_root(levels)

    print("Merkle Root:")
    print(root)

    # Generate proof for the second record
    index = 1
    proof = generate_proof(levels, index)

    print("\nInclusion Proof:")
    print(proof)

    # Verify the original record
    valid = verify_proof(
        leaves[index],
        proof,
        root
    )

    print("\nValid proof:", valid)
    assert valid, "Valid proof should pass"

    # Attempt verification using a modified record hash
    invalid = verify_proof(
        "f" * 64,
        proof,
        root
    )

    print("Modified leaf accepted:", invalid)
    assert not invalid, "Modified leaf should fail"

    print("\nSUCCESS: Merkle inclusion verification works.")


if __name__ == "__main__":
    run_test()
