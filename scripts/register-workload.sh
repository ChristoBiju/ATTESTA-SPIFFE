#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPIRE_DIR="$ROOT/infrastructure/spire/spire-1.15.3"

SERVER_BIN="$SPIRE_DIR/bin/spire-server"
SOCKET="/tmp/spire-server/private/api.sock"
WORKLOAD_ID="spiffe://attesta.example.org/ci/build-runner"
SELECTOR="unix:uid:$(id -u)"

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <full-parent-agent-spiffe-id>"
    echo
    echo "Find the parent ID with:"
    echo "  $SPIRE_DIR/bin/spire-server agent list -socketPath $SOCKET"
    exit 2
fi

PARENT_ID="$1"

if [[ "$PARENT_ID" != spiffe://attesta.example.org/* ]]; then
    echo "ERROR: Parent ID must belong to attesta.example.org."
    exit 2
fi

if [[ ! -x "$SERVER_BIN" ]]; then
    echo "ERROR: SPIRE Server binary not found."
    exit 1
fi

"$SERVER_BIN" entry create \
    -socketPath "$SOCKET" \
    -parentID "$PARENT_ID" \
    -spiffeID "$WORKLOAD_ID" \
    -selector "$SELECTOR"

echo
echo "Workload registration requested:"
echo "  SPIFFE ID: $WORKLOAD_ID"
echo "  Selector:  $SELECTOR"
