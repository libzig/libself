# libself

`did:key` identity/auth/trust library in Zig.

## Overview

`libself` is focused on small, local-first identity.

- Ed25519 key-backed identities
- deterministic `NodeId` derivation from the same public key
- local `did:key` encode/parse/resolve
- challenge-response authentication bound to transcript context
- trust modes: `accept_any`, `tofu`, `pinned`
- attached identity flow for `libfast` connections

In short: if your product needs a compact identity layer with no registry and no hosted resolver, this is the package.

## Build and Test

```bash
make build
zig build test --summary all
```

## Quick Start (Examples)

```bash
zig build run-did-key-roundtrip
zig build run-auth-challenge
zig build run-trust-tofu
zig build run-libfast-identity-handshake
```

## Docs

- See `docs/` for library and integration documentation.

## Acknowledgments

- See `ACKNOWLEDGMENTS.md`.

## Version

- Current package version: `0.0.1`
