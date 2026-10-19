import json
import hashlib
import base64

from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey
)
from cryptography.exceptions import InvalidSignature

from ledger_merkle import build_ledger_merkle_tree


BASE_DIR = Path(__file__).resolve().parent
KEY_DIR = BASE_DIR / "checkpoint_keys"

PRIVATE_KEY_PATH = KEY_DIR / "checkpoint_private.pem"
PUBLIC_KEY_PATH = KEY_DIR / "checkpoint_public.pem"


def canonical_json(data):
    """Serialize checkpoint data deterministically."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")


def initialize_keys():
    """
    Generate an Ed25519 key pair if one does not already exist.

    These keys are for the local prototype. Production key
    management should use a separately protected key store.
    """
    KEY_DIR.mkdir(parents=True, exist_ok=True)

    if PRIVATE_KEY_PATH.exists() or PUBLIC_KEY_PATH.exists():
        if not (
            PRIVATE_KEY_PATH.exists()
            and PUBLIC_KEY_PATH.exists()
        ):
            raise RuntimeError(
                "Only one checkpoint key exists. "
                "Restore the matching key pair securely."
            )
        return

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Restrict access to the private key on POSIX systems.
    PRIVATE_KEY_PATH.write_bytes(private_bytes)
    PRIVATE_KEY_PATH.chmod(0o600)

    PUBLIC_KEY_PATH.write_bytes(public_bytes)

    print("Checkpoint signing keys generated.")


def load_private_key():
    initialize_keys()

    return serialization.load_pem_private_key(
        PRIVATE_KEY_PATH.read_bytes(),
        password=None
    )


def load_public_key():
    initialize_keys()

    return serialization.load_pem_public_key(
        PUBLIC_KEY_PATH.read_bytes()
    )


def create_checkpoint():
    """Create a signed checkpoint for the current ledger state."""

    records, levels, merkle_root = build_ledger_merkle_tree()

    # Do not checkpoint an internally inconsistent hash chain.
    from attestation_ledger import verify_chain

    chain_result = verify_chain()

    if not chain_result["valid"]:
        raise ValueError(
            "Cannot checkpoint an invalid ledger: "
            + chain_result["reason"]
        )

    checkpoint = {
        "version": 1,
        "record_count": len(records),
        "merkle_root": merkle_root,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    private_key = load_private_key()

    signature = private_key.sign(canonical_json(checkpoint))

    checkpoint["signature"] = base64.b64encode(
        signature
    ).decode("ascii")

    return checkpoint


def verify_checkpoint(checkpoint):
    """Verify the signature on checkpoint metadata."""

    try:
        unsigned_checkpoint = {
            key: value
            for key, value in checkpoint.items()
            if key != "signature"
        }

        signature = base64.b64decode(
            checkpoint["signature"],
            validate=True
        )

        public_key = load_public_key()

        public_key.verify(
            signature,
            canonical_json(unsigned_checkpoint)
        )

        return True

    except (
        InvalidSignature,
        KeyError,
        ValueError,
        TypeError
    ):
        return False


def verify_checkpoint_root(checkpoint):
    """
    Verify the signed checkpoint and compare it with the current ledger.

    The hash chain must be valid before the Merkle root is trusted.
    """

    if not verify_checkpoint(checkpoint):
        return {
            "valid": False,
            "reason": "Checkpoint signature is invalid"
        }

    try:
        from attestation_ledger import verify_chain

        # Step 1: Verify the actual record contents and hash chain.
        chain_result = verify_chain()

        if not chain_result["valid"]:
            return {
                "valid": False,
                "reason": "Ledger integrity verification failed",
                "details": chain_result
            }

        # Step 2: Recalculate the Merkle root from the ledger.
        records, levels, current_root = build_ledger_merkle_tree()

        # Step 3: Check that the record count matches.
        if len(records) != checkpoint["record_count"]:
            return {
                "valid": False,
                "reason": "Ledger record count does not match checkpoint"
            }

        # Step 4: Compare against the signed Merkle root.
        if current_root != checkpoint["merkle_root"]:
            return {
                "valid": False,
                "reason": "Merkle root does not match checkpoint"
            }

        return {
            "valid": True,
            "message": "Ledger matches the signed checkpoint"
        }

    except (ValueError, KeyError, TypeError) as exc:
        return {
            "valid": False,
            "reason": str(exc)
        }

if __name__ == "__main__":
    checkpoint = create_checkpoint()

    print("\nSigned checkpoint:")
    print(json.dumps(checkpoint, indent=2))

    print("\nSignature valid:", verify_checkpoint(checkpoint))

    print("\nLedger verification:")
    print(json.dumps(verify_checkpoint_root(checkpoint), indent=2))
