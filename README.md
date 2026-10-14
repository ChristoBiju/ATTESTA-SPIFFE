# Attesta — SPIFFE/SPIRE Prototype

Attesta is a zero-trust runtime identity and policy enforcement framework for
CI/CD pipelines.

This repository contains the initial SPIFFE/SPIRE workload identity prototype.

## Current milestone

- SPIRE 1.15.3 local development setup
- Trust domain: `attesta.example.org`
- Test workload: `spiffe://attesta.example.org/ci/build-runner`
- Default X.509-SVID TTL: 24 hours
- Example configuration and helper scripts

## Getting started

See [SPIRE setup instructions](docs/SPIRE-SETUP.md).

## Security

This is a development prototype. The current insecure bootstrap and Unix UID
selector are not suitable for production CI/CD deployments. Never commit
join tokens, private keys, SVID private-key material, or runtime databases.

## Project status

Hyperledger Fabric integration, custom attestation APIs, Merkle proofs, and
CI/CD policy enforcement are future implementation milestones.
