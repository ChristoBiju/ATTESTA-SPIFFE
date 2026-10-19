import sqlite3
import tempfile
from pathlib import Path

import attestation_ledger as ledger
from attestation_ledger import calculate_hash, verify_chain
from checkpoint import create_checkpoint, verify_checkpoint_root


def run_test():
    print("=== ATTESTA Full-Chain Rewrite Test ===")

    original_db_path = ledger.DB_PATH

    with tempfile.TemporaryDirectory() as temp_dir:
        ledger.DB_PATH = Path(temp_dir) / "test_attestations.db"

        try:
            # Create two valid records.
            first = ledger.create_attestation(
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

            # Sign the original state.
            checkpoint = create_checkpoint()

            print("\nTest 1: Original ledger")
            print(verify_checkpoint_root(checkpoint))

            # Simulate an attacker rewriting the entire hash chain.
            connection = sqlite3.connect(ledger.DB_PATH)

            try:
                rows = connection.execute("""
                    SELECT *
                    FROM attestations
                    ORDER BY sequence ASC
                """).fetchall()

                previous_hash = ledger.GENESIS_HASH

                for row in rows:
                    (
                        sequence,
                        attestation_id,
                        workload_spiffe_id,
                        artifact_digest,
                        policy_decision,
                        evidence_hash,
                        timestamp,
                        old_previous_hash,
                        old_record_hash
                    ) = row

                    # Change the first record's decision.
                    if attestation_id == first["attestation_id"]:
                        policy_decision = "DENY"

                    record = {
                        "attestation_id": attestation_id,
                        "workload_spiffe_id": workload_spiffe_id,
                        "artifact_digest": artifact_digest,
                        "policy_decision": policy_decision,
                        "evidence_hash": evidence_hash,
                        "timestamp": timestamp,
                        "previous_record_hash": previous_hash
                    }

                    new_hash = calculate_hash(record)

                    connection.execute("""
                        UPDATE attestations
                        SET policy_decision = ?,
                            previous_record_hash = ?,
                            record_hash = ?
                        WHERE attestation_id = ?
                    """, (
                        policy_decision,
                        previous_hash,
                        new_hash,
                        attestation_id
                    ))

                    previous_hash = new_hash

                connection.commit()

            finally:
                connection.close()

            # The attacker recalculated the chain, so the chain
            # may be internally consistent despite the modification.
            chain_result = verify_chain()

            print("\nTest 2: Rewritten hash chain")
            print(chain_result)

            assert chain_result["valid"], (
                "The rewritten chain should be internally consistent"
            )

            # The old signed checkpoint must reject the rewritten state.
            checkpoint_result = verify_checkpoint_root(checkpoint)

            print("\nTest 3: Compare rewritten ledger with old checkpoint")
            print(checkpoint_result)

            assert not checkpoint_result["valid"], (
                "The old checkpoint must reject the rewritten ledger"
            )

            print(
                "\nSUCCESS: The rewritten chain passed internal "
                "verification but did not match the original checkpoint."
            )

        finally:
            ledger.DB_PATH = original_db_path


if __name__ == "__main__":
    run_test()
