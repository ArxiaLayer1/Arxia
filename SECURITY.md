# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public issue
2. Email the security report to the project maintainers
3. Include steps to reproduce the vulnerability
4. Allow reasonable time for a fix before public disclosure

## Scope

Security issues in the following areas are in scope:

- Cryptographic implementations (Ed25519, Blake3, ChaCha20)
- Consensus logic (ORV, conflict resolution, quorum)
- Double-spend detection
- Gossip protocol integrity
- Smart contract sandbox escapes
- Key management and storage

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes      |
