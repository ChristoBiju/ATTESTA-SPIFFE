#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPIRE_DIR="$ROOT/infrastructure/spire/spire-1.15.3"
CONFIG="$ROOT/infrastructure/spire/config/agent.conf.example"

if [[ ! -x "$SPIRE_DIR/bin/spire-agent" ]]; then
    echo "ERROR: SPIRE Agent binary not found. Follow docs/SPIRE-SETUP.md."
    exit 1
fi

if [[ ! -f "$CONFIG" ]]; then
    echo "ERROR: Agent configuration not found: $CONFIG"
    exit 1
fi

read -r -s -p "Paste the fresh SPIRE join token: " JOIN_TOKEN
echo

if [[ -z "$JOIN_TOKEN" ]]; then
    echo "ERROR: No join token provided."
    exit 1
fi

cd "$SPIRE_DIR"
exec ./bin/spire-agent run -config "$CONFIG" -joinToken "$JOIN_TOKEN"
