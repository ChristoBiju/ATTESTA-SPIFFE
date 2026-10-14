#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPIRE_DIR="$ROOT/infrastructure/spire/spire-1.15.3"

echo "Checking Attesta SPIRE development environment..."

for cmd in git curl openssl sha256sum; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: Required command not found: $cmd"
        exit 1
    fi
    echo "OK: $cmd"
done

if [[ ! -x "$SPIRE_DIR/bin/spire-server" ||
      ! -x "$SPIRE_DIR/bin/spire-agent" ]]; then
    echo "ERROR: SPIRE 1.15.3 binaries not found at:"
    echo "  $SPIRE_DIR"
    echo "Read docs/SPIRE-SETUP.md for installation instructions."
    exit 1
fi

echo "OK: SPIRE server and agent binaries found."
"$SPIRE_DIR/bin/spire-server" --version
"$SPIRE_DIR/bin/spire-agent" --version

echo "Prerequisite check completed."
