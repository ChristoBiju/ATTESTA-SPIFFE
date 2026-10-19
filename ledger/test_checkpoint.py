import json
import sqlite3
import tempfile
from pathlib import Path

import attestation_ledger as ledger
from checkpoint import create_checkpoint, verify_checkpoint, verify_checkpoint_root


def run_test():
    print("=== ATTESTA Signed Checkpoint Test ===")

    original_db_path = ledger.DB_PATH

    with tempfile.TemporaryDirectory() as temp_dir:
        ledger.DB_PATH = Path(temp_dir) / "test_attestations.db"

        try:
            # Test 1: Create two clean records.
            record1 = ledger.create_attestation(
                workload_spiffe_id=(
                    "spiffe://attesta.example.org/ci/build-runner"
                ),
                artifact_digest="sha256:artifact001",
                policy_decision="ALLOW",
                evidence_hash="sha256:evidence001"
            )

            ledger.create_attestation(
                workload_spiffe_id=(
                    "spiffe://attesta.example.org/ci/build-runner"
                ),
                artifact_digest="sha256:artifact002",
                policy_decision="DENY",
                evidence_hash="sha256:evidence002"
            )

            print("\nTest 1: Clean ledger created")
            print(json.dumps(ledger.verify_chain(), indent=2))

            # Test 2: Create a signed checkpoint.
            checkpoint = create_checkpoint()

            print("\nTest 2: Checkpoint signature valid")
            print(verify_checkpoint(checkpoint))

            # Test 3: Verify the ledger against the checkpoint.
            result = verify_checkpoint_root(checkpoint)

            print("\nTest 3: Original ledger matches checkpoint")
            print(json.dumps(result, indent=2))

            assert result["valid"]

            # Test 4: Tamper with the database after checkpoint creation.
            connection = sqlite3.connect(ledger.DB_PATH)

            try:
                connection.execute(
                    """
                    UPDATE attestations
                    SET policy_decision = 'DENY'
                    WHERE attestation_id = ?
                    """,
                    (record1["attestation_id"],)
                )

                connection.commit()

            finally:
                connection.close()

            # The signed checkpoint should remain valid,
            # but the changed ledger should no longer match it.
            assert verify_checkpoint(checkpoint)

            result = verify_checkpoint_root(checkpoint)

            print("\nTest 4: Ledger after tampering")
            print(json.dumps(result, indent=2))

            assert not result["valid"]

            print("\nSUCCESS: Checkpoint test passed.")

        finally:
            ledger.DB_PATH = original_db_path


if __name__ == "__main__":
    run_test()
