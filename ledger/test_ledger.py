import sqlite3
import json
import tempfile
import os

import attestation_ledger as ledger

from attestation_ledger import (
    create_attestation,
    get_attestations,
    verify_chain,
    DB_PATH
)

WORKLOAD_ID = "spiffe://attesta.example.org/ci/build-runner"

def run_tests():
    print("\n=== ATTESTA Ledger Test ===")

    # Create a separate temporary database for this test.
    with tempfile.TemporaryDirectory() as temp_dir:
        test_db = os.path.join(temp_dir, "test_attestations.db")

        # Redirect the ledger to the temporary database.
        original_db_path = ledger.DB_PATH
        ledger.DB_PATH = test_db

        try:
            # Test 1: Create the first record.
            record1 = ledger.create_attestation(
                workload_spiffe_id=(
                    "spiffe://attesta.example.org/ci/build-runner"
                ),
                artifact_digest="sha256:artifact001",
                policy_decision="ALLOW",
                evidence_hash="sha256:evidence001"
            )

            print("\nTest 1: First record created")
            print("Attestation ID:", record1["attestation_id"])

            # Test 2: Create the second record.
            record2 = ledger.create_attestation(
                workload_spiffe_id=(
                    "spiffe://attesta.example.org/ci/build-runner"
                ),
                artifact_digest="sha256:artifact002",
                policy_decision="DENY",
                evidence_hash="sha256:evidence002"
            )

            print("\nTest 2: Second record created")
            print("Attestation ID:", record2["attestation_id"])

            # Test 3: Verify the intact ledger.
            result = ledger.verify_chain()

            print("\nTest 3: Verify intact ledger")
            print(json.dumps(result, indent=2))

            assert result["valid"], "Intact ledger should pass verification"

            # Test 4: Modify a record directly in the test database.
            connection = sqlite3.connect(test_db)

            try:
                connection.execute(
                    """
                    UPDATE attestations
                    SET policy_decision = 'ALLOW'
                    WHERE attestation_id = ?
                    """,
                    (record2["attestation_id"],)
                )

                connection.commit()

            finally:
                connection.close()

            # Test 5: Verify that tampering is detected.
            result = ledger.verify_chain()

            print("\nTest 5: Verify after tampering")
            print(json.dumps(result, indent=2))

            assert not result["valid"], "Tampering should be detected"

            print("\nSUCCESS: All ledger tests passed.")

        finally:
            # Restore the original database location.
            ledger.DB_PATH = original_db_path


if __name__ == "__main__":
    run_tests()
