# Acknowledgments

No one writes identity and transport software in a vacuum. We definitely didn't.

## Companion packages

These packages shape how `libself` is built and integrated:

- **[`libsafe`](https://github.com/libzig/libsafe)** for Ed25519 keys and signature operations
- **[`libfast`](https://github.com/libzig/libfast)** for QUIC transport integration and attached connection identity flow

## Protocol and standards references

These references informed identity format, resolution, and authentication behavior:

- **[`did:key` Method](https://w3c-ccg.github.io/did-key-spec/)**
- **[W3C DID Core 1.1](https://www.w3.org/TR/did-1.1/)**
- **[W3C DID Resolution](https://www.w3.org/TR/did-resolution/)**
- **[Multibase](https://datatracker.ietf.org/doc/html/draft-multiformats-multibase-08)**
- **[Multicodec](https://github.com/multiformats/multicodec)**
- **[Ed25519 (RFC 8032)](https://www.rfc-editor.org/rfc/rfc8032.html)**
- **[QUIC Transport (RFC 9000)](https://www.rfc-editor.org/rfc/rfc9000.html)**

## Ecosystem references

- **[OpenSSH Portable](https://github.com/openssh/openssh-portable)** for long-standing TOFU and key-pinning operational patterns

Thank you to everyone publishing open standards, reference material, and working implementations. You made this possible.
