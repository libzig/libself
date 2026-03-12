# libself Documentation

## What this package does

`libself` implements a small identity layer centered on `did:key`.

It provides:

- Ed25519 identity generation and handling
- deterministic `NodeId` derivation
- local `did:key` encoding, parsing, and DID document derivation
- challenge-response authentication tied to transcript context
- trust policy and pin storage
- optional attachment of authenticated peer identity to `libfast` connections

## Identity shape

The core model is intentionally simple:

1. private key
2. public key
3. `did:key`
4. derived DID document
5. challenge/proof
6. trust decision
7. optional attached peer identity on a `libfast` connection wrapper

## Main library areas

- `lib/identity.zig`
  - Ed25519 key handling wrapper
- `lib/node_id.zig`
  - compact transport identity derived from the public key
- `lib/did/`
  - `did:key` codec, derived document, local resolver
- `lib/auth/`
  - challenge and proof logic
- `lib/trust/`
  - trust policy, in-memory store, file persistence
- `lib/profile.zig`
  - metadata layer kept separate from DID resolution
- `lib/libfast/`
  - `adapter.zig`: transport-facing role/state helpers
  - `binding.zig`: transcript/channel binding derivation
  - `local_identity.zig`: keypair + derived DID convenience wrapper
  - `session.zig`: connection-bound auth helpers
  - `attached.zig`: authenticated connection wrapper

## Typical usage flow

Library flow:

1. Generate or load an Ed25519 identity.
2. Derive a `did:key` and `NodeId`.
3. Resolve the DID locally when verification is needed.
4. Challenge the peer and verify the returned proof.
5. Apply trust mode (`accept_any`, `tofu`, or `pinned`).

`libfast` flow:

1. Start from a handshake-ready `libfast.QuicConnection`.
2. Wrap it in `LibfastAuthenticatedConnection`.
3. Build a challenge from the attached connection binding.
4. Verify the peer proof and attach the resolved peer identity to the wrapper.

## Examples

- `examples/hello_world.zig`
- `examples/did_key_roundtrip.zig`
- `examples/auth_challenge.zig`
- `examples/trust_tofu.zig`
- `examples/profile_roundtrip.zig`
- `examples/libfast_identity_handshake.zig`

## Build and test

```bash
make build
zig build test --summary all
```

## Version

- `0.0.1`
