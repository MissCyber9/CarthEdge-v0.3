# CarthEdge (v0.1)

Secure messenger built to be strictly the best under adversarial conditions.

**Non-negotiable:**
- Wallet-based identity (no phone/email)
- No centralized identity
- No permanent identifiers
- Key rotation + recovery governed by QKeyRotationV1
- Explicit introspection UX via explainBlockers()
- Relay is ciphertext-only (no plaintext, no keys)

## Roadmap (high level)
- v0.1: cryptographic kernel + 1:1 messaging + QKeyRotation governance integration
- v0.2: groups + multi-device + offline queue
- v0.3: channels + broadcast structures (Telegram-like but zero-trust)
- v0.4+: bots + coins + federation

## Repo layout
- `docs/` architecture, threat model, protocol specs
- `specs/` API contracts and schemas
- `clients/` iOS + Android apps
- `relay/` minimal store-forward relay (ciphertext-only)
- `tooling/` test vectors + adversary simulations
