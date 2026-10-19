import os
import sqlite3
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


# Database location
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(
    os.environ.get("ATTESTA_DB_PATH", str(BASE_DIR / "attestations.db"))
)

GENESIS_HASH = "GENESIS"


def calculate_hash(record):
    """
    Calculate the SHA-256 hash of a record.

    The hash is calculated from a deterministic JSON
    representation of the record.
    """
    record_data = json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":")
    )

    return hashlib.sha256(record_data.encode("utf-8")).hexdigest()


def connect_db():
    """Create a database connection and initialize the table."""

    connection = sqlite3.connect(DB_PATH)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS attestations (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            attestation_id TEXT UNIQUE NOT NULL,
            workload_spiffe_id TEXT NOT NULL,
            artifact_digest TEXT NOT NULL,
            policy_decision TEXT NOT NULL,
            evidence_hash TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            previous_record_hash TEXT NOT NULL,
            record_hash TEXT NOT NULL
        )
    """)

    return connection


def create_attestation(
    workload_spiffe_id,
    artifact_digest,
    policy_decision,
    evidence_hash
):
    """
    Append a new attestation record to the ledger.
    """

    if not workload_spiffe_id.startswith("spiffe://"):
        raise ValueError("Invalid SPIFFE ID format")

    if policy_decision not in ("ALLOW", "DENY"):
        raise ValueError("Policy decision must be ALLOW or DENY")

    if not artifact_digest.startswith("sha256:"):
        raise ValueError("Artifact digest must use the sha256: format")

    if not evidence_hash.startswith("sha256:"):
        raise ValueError("Evidence hash must use the sha256: format")

    connection = connect_db()

    try:
        # Read the most recent record.
        previous = connection.execute("""
            SELECT record_hash
            FROM attestations
            ORDER BY sequence DESC
            LIMIT 1
        """).fetchone()

        previous_hash = previous[0] if previous else GENESIS_HASH

        # Construct the attestation record.
        record = {
            "attestation_id": str(uuid.uuid4()),
            "workload_spiffe_id": workload_spiffe_id,
            "artifact_digest": artifact_digest,
            "policy_decision": policy_decision,
            "evidence_hash": evidence_hash,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "previous_record_hash": previous_hash
        }

        # Calculate the hash before inserting the record.
        record_hash = calculate_hash(record)

        connection.execute("""
            INSERT INTO attestations (
                attestation_id,
                workload_spiffe_id,
                artifact_digest,
                policy_decision,
                evidence_hash,
                timestamp,
                previous_record_hash,
                record_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            record["attestation_id"],
            record["workload_spiffe_id"],
            record["artifact_digest"],
            record["policy_decision"],
            record["evidence_hash"],
            record["timestamp"],
            record["previous_record_hash"],
            record_hash
        ))

        connection.commit()

        record["record_hash"] = record_hash

        return record

    finally:
        connection.close()


def get_attestations():
    """Return all records in ledger order."""

    connection = connect_db()

    try:
        connection.row_factory = sqlite3.Row

        rows = connection.execute("""
            SELECT *
            FROM attestations
            ORDER BY sequence ASC
        """).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def verify_chain():
    """
    Verify each record hash and the links between records.
    """

    records = get_attestations()
    expected_previous_hash = GENESIS_HASH

    for record in records:
        # Reconstruct the fields used to calculate the hash.
        hash_input = {
            "attestation_id": record["attestation_id"],
            "workload_spiffe_id": record["workload_spiffe_id"],
            "artifact_digest": record["artifact_digest"],
            "policy_decision": record["policy_decision"],
            "evidence_hash": record["evidence_hash"],
            "timestamp": record["timestamp"],
            "previous_record_hash": record["previous_record_hash"]
        }

        # Check the link to the preceding record.
        if record["previous_record_hash"] != expected_previous_hash:
            return {
                "valid": False,
                "failed_record": record["attestation_id"],
                "reason": "Previous record hash mismatch"
            }

        # Recalculate the current record's hash.
        calculated_hash = calculate_hash(hash_input)

        if calculated_hash != record["record_hash"]:
            return {
                "valid": False,
                "failed_record": record["attestation_id"],
                "reason": "Record hash mismatch"
            }

        expected_previous_hash = record["record_hash"]

    return {
        "valid": True,
        "records_checked": len(records),
        "message": "Ledger integrity verified"
    }


if __name__ == "__main__":
    print("ATTESTA Attestation Ledger")
    print("-------------------------")

    print("\nCurrent records:")
    print(json.dumps(get_attestations(), indent=2))

    print("\nIntegrity verification:")
    print(json.dumps(verify_chain(), indent=2))
