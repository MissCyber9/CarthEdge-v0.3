# CarthEdge — v0.3.5 (Frozen)

CarthEdge is a **security-first, offline-capable communication core** designed for
high-risk, high-sovereignty environments.

Version **v0.3.5** is a **frozen architectural milestone**.
It establishes a **rigorous cryptographic and governance foundation** upon which
higher-level features will be built in v0.4.x and beyond.

---

## 🎯 Scope of v0.3.x

This version focuses exclusively on **core correctness, auditability, and invariants**.

No UI.  
No networking assumptions.  
No persistent identity leakage.

Everything here is **testable offline**.

---

## ✅ What is implemented in v0.3.5

### 🔐 Ratchet Core (Signal-like, governance-aware)

- `RatchetState`
  - Symmetric ratchet with:
    - `step_send`
    - `step_recv`
  - **Strict monotonic counters**
    - `send_counter`
    - `recv_counter`
    - `prev_send_counter`
  - Replay-safe logic (counter-based)
  - Explicit `Locked / Running` states
- Deterministic HKDF-based key derivation
- Clear separation:
  - root key
  - send chain
  - receive chain
- **QKeyRotation (QKR) gate integration**
  - Every sensitive operation is gated
  - Offline test gate (`AllowAllGate`) provided

### 🔑 Cryptographic Primitives

- HKDF (SHA-256)
- ChaCha20-Poly1305 (AEAD)
- Explicit labels for all derivations
- No implicit crypto behavior

### 📦 Envelope Layer

- `EnvelopeV2`
  - Authenticated encryption
  - Header-bound AAD
  - Explicit message typing
- Tamper detection is enforced by construction

### 👥 Channel Primitives (Foundation only)

- `ChannelState`
  - Member list
  - Channel `epoch`
  - QKR-gated `rotate()` operation
- `ChannelMember`
  - Owns an independent `RatchetState`
- Designed for:
  - pairwise ratcheted group messaging
  - replay/out-of-order handling (extended in v0.4)

### 🧪 Tests (Offline, Deterministic)

- Ratchet invariants:
  - send/recv counters monotonicity
  - locked state enforcement
- Channel invariants:
  - epoch rotation
  - member isolation
- Replay and ordering tests (foundation)
- All tests run **without network, time, or randomness leaks**

---

## 🚫 Explicitly NOT included in v0.3.x

- ❌ Networking / transport
- ❌ Identity layer
- ❌ Persistent storage
- ❌ Group broadcast semantics
- ❌ UI / mobile / API
- ❌ Production key management

These are **deliberately deferred** to preserve auditability.

---

## 🧱 Architectural Philosophy

- **Core before features**
- **Governance before convenience**
- **Determinism before performance**
- **Auditability before scale**

This core is designed to survive:
- adversarial audits
- formal verification
- long-term cryptographic evolution

---

## 🔒 Status

**v0.3.5 is FROZEN.**

No further changes will be made to this line except for critical security fixes.

All new development continues in **v0.4.x**.

---

## 📜 License

MIT (core logic intentionally open for verification).

---

## ✨ Next milestone

➡️ **v0.4.x**
- Channel receive pipeline
- Replay / out-of-order resolution
- Epoch-aware skipped-key store
- Forced recovery semantics
- Formal threat-model alignment

See the v0.4 prompt for details.
 minimal store-forward relay (ciphertext-only)
- `tooling/` test vectors + adversary simulations
