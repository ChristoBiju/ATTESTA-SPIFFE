#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPIRE_DIR="$ROOT/infrastructure/spire/spire-1.15.3"
CONFIG="$ROOT/infrastructure/spire/config/server.conf.example"

if [[ ! -x "$SPIRE_DIR/bin/spire-server" ]]; then
    echo "ERROR: SPIRE Server binary not found. Follow docs/SPIRE-SETUP.md."
    exit 1
fi

if [[ ! -f "$CONFIG" ]]; then
    echo "ERROR: Server configuration not found: $CONFIG"
    exit 1
fi

# Relative paths in the configuration resolve from the SPIRE directory.
cd "$SPIRE_DIR"
exec ./bin/spire-server run -config "$CONFIG"
