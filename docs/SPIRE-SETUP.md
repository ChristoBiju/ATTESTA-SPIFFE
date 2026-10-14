# Reproducing the Attesta SPIRE Prototype

## Scope

This guide runs the initial SPIFFE/SPIRE prototype on Ubuntu or Ubuntu under
WSL2. It uses SPIRE 1.15.3 and the trust domain `attesta.example.org`.

## 1. Clone the repository

    git clone https://github.com/ChristoBiju/ATTESTA-SPIFFE.git
    cd ATTESTA-SPIFFE

## 2. Install prerequisites

Install Git, curl, OpenSSL, and the usual Linux build utilities using your
distribution's package manager.

Run:

    bash scripts/check-prerequisites.sh

## 3. Install the SPIRE distribution

Download the official SPIRE 1.15.3 Linux AMD64 release from:

https://github.com/spiffe/spire/releases/tag/v1.15.3

Verify the downloaded archive against the checksum published by the official
release before extracting it.

Extract the release so that these files exist:

    infrastructure/spire/spire-1.15.3/bin/spire-server
    infrastructure/spire/spire-1.15.3/bin/spire-agent

The downloaded distribution is intentionally excluded from Git.

## 4. Start the SPIRE Server

In terminal 1:

    bash scripts/start-server.sh

Keep this terminal open.

## 5. Check server health

In terminal 2, run:

    infrastructure/spire/spire-1.15.3/bin/spire-server healthcheck \
      -socketPath /tmp/spire-server/private/api.sock

Expected result:

    Server is healthy.

## 6. Generate a fresh agent join token

In terminal 2:

    infrastructure/spire/spire-1.15.3/bin/spire-server token generate \
      -socketPath /tmp/spire-server/private/api.sock \
      -spiffeID spiffe://attesta.example.org/host/agent

Treat the token as a secret. Do not commit or share it. Use it promptly.

## 7. Start the SPIRE Agent

In terminal 3:

    bash scripts/start-agent.sh

Paste the join token when prompted. Keep this terminal open.

## 8. Find the current agent ID

In terminal 2:

    infrastructure/spire/spire-1.15.3/bin/spire-server agent list \
      -socketPath /tmp/spire-server/private/api.sock

Copy the full SPIFFE ID of the newly attested agent.

## 9. Register the test workload

In terminal 2, substitute the full agent SPIFFE ID:

    bash scripts/register-workload.sh \
      'spiffe://attesta.example.org/spire/agent/join_token/REPLACE_WITH_REAL_ID'

Use the complete value printed by `agent list`, not the placeholder above.

## 10. Fetch an X.509-SVID

Use the Workload API socket exposed by the agent:

    infrastructure/spire/spire-1.15.3/bin/spire-agent api fetch x509 \
      -socketPath /tmp/spire-agent/public/api.sock

The output can contain private-key material. Do not commit or share the output.
Inspect the certificate locally and verify its SPIFFE ID and certificate chain.

## Development-only security limitations

- `insecure_bootstrap = true` is for local testing only.
- Join-token attestation does not by itself prove a CI runner is trustworthy.
- The Unix UID selector is only a local development selector.
- Runtime keys, databases, tokens, SVIDs, and private keys must remain outside Git.
- This guide is not a production deployment guide.
