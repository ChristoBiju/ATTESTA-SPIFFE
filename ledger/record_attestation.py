import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

from attestation_ledger import create_attestation


EXPECTED_SPIFFE_ID = "spiffe://attesta.example.org/ci/build-runner"


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_openssl(*args):
    result = subprocess.run(
        ["openssl", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "OpenSSL verification failed")
    return result.stdout


def verify_svid(svid_path, bundle_path, expected_spiffe_id):
    # Verify the certificate chain and certificate validity against the bundle.
    run_openssl(
        "verify",
        "-CAfile", str(bundle_path),
        str(svid_path),
    )

    # Extract the certificate's URI SAN.
    san_output = run_openssl(
        "x509",
        "-in", str(svid_path),
        "-noout",
        "-ext", "subjectAltName",
    )

    uri_ids = re.findall(r"URI:(spiffe://[^,\s]+)", san_output)

    if uri_ids.count(expected_spiffe_id) != 1:
        raise ValueError(
            f"Expected exactly one URI SAN matching {expected_spiffe_id}; "
            f"found {uri_ids}"
        )

    # Record only public certificate/bundle fingerprints as evidence.
    return {
        "spiffe_id": expected_spiffe_id,
        "svid_sha256": sha256_file(svid_path),
        "bundle_sha256": sha256_file(bundle_path),
        "verification": "openssl_chain_and_validity_check",
    }


def main():
    parser = argparse.ArgumentParser(
        description="Verify a local SPIRE SVID and record an ATTESTA ledger entry."
    )
    parser.add_argument("artifact", type=Path)
    parser.add_argument(
        "--decision",
        required=True,
        choices=("ALLOW", "DENY"),
        help="Explicit test decision; this script does not evaluate OPA policies.",
    )
    parser.add_argument(
        "--svid",
        type=Path,
        default=Path("/tmp/attesta-svid/svid.0.pem"),
    )
    parser.add_argument(
        "--bundle",
        type=Path,
        default=Path("/tmp/attesta-svid/bundle.0.pem"),
    )
    parser.add_argument(
        "--spiffe-id",
        default=EXPECTED_SPIFFE_ID,
    )
    args = parser.parse_args()

    for path in (args.artifact, args.svid, args.bundle):
        if not path.is_file():
            raise FileNotFoundError(f"Required file not found: {path}")

    evidence = verify_svid(
        args.svid,
        args.bundle,
        args.spiffe_id,
    )

    artifact_digest = "sha256:" + sha256_file(args.artifact)

    evidence_json = json.dumps(
        evidence,
        sort_keys=True,
        separators=(",", ":"),
    )
    evidence_hash = "sha256:" + hashlib.sha256(
        evidence_json.encode("utf-8")
    ).hexdigest()

    record = create_attestation(
        workload_spiffe_id=evidence["spiffe_id"],
        artifact_digest=artifact_digest,
        policy_decision=args.decision,
        evidence_hash=evidence_hash,
    )

    print("SVID verification: PASSED")
    print(f"SPIFFE ID: {evidence['spiffe_id']}")
    print(f"Artifact digest: {artifact_digest}")
    print(f"Evidence hash: {evidence_hash}")
    print(f"Policy decision (explicit test input): {args.decision}")
    print(f"Attestation ID: {record['attestation_id']}")
    print(f"Record hash: {record['record_hash']}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, FileNotFoundError) as error:
        raise SystemExit(f"ERROR: {error}")
