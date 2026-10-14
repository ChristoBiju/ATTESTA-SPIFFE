# Attesta — SPIFFE/SPIRE Identity

## Status

Initial local development prototype using SPIRE 1.15.3.

## Implemented

- Configured the SPIRE Server and Agent.
- Set the trust domain to `attesta.example.org`.
- Configured a default X.509-SVID TTL of 24 hours.
- Registered the workload identity:
  `spiffe://attesta.example.org/ci/build-runner`
- Configured a Unix UID selector for local testing.

## Development configuration

Example configurations are in `config/`.

The original SPIRE distribution and runtime state are not tracked in Git.
Runtime keys, databases, SVID private keys, and join tokens must not be committed.

## Security limitations

The current setup uses join-token attestation and insecure bootstrap for local
development only. The Unix UID selector is not sufficient to establish trust
in a remote CI/CD runner. Production deployment requires a stronger bootstrap
and workload-attestation design.

## Next steps

- Verify X.509-SVID issuance and certificate validity.
- Test denial for unregistered workloads.
- Test SVID renewal and expiration.
- Design the integration between workload identity and the Attesta ledger.
