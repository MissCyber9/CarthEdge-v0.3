# CarthEdge v0.3 — QKeyRotation-Governed Double Ratchet (Spec)

## 0. Design intent (what we optimize for)
We implement a Signal-like Double Ratchet messaging layer (X25519 DH ratchet + symmetric chains),
but **every sensitive state transition is governed by QKeyRotationV1** and **bound to an op_context**.

CarthEdge constraints:
- **No permanent identifiers** in ratchet state or messages (no static long-lived IDs).
- **No trusted relay** assumption (relay may be malicious, reorder, replay, drop).
- **Explicit introspection states** (clear failure modes; stable reason codes).
- **Forward Secrecy** + **Post-Compromise Safety (PCS)**.
- SDK-only; offline-first deterministic tests.

Non-negotiables:
- Ratchet state transitions MUST be gated by QKeyRotation.
- All sensitive ops require op_context binding (canonical bytes).
- Replay protection MUST be explicit and testable.
- Tests MUST be fast + offline.

---

## 1. Primitives and notation

### 1.1 Cryptographic primitives
- DH: X25519
- KDF: HKDF-SHA256 (domain-separated labels)
- AEAD: Provided by EnvelopeV2 (already stable in v0.2)
- Hash: SHA-256 for binder hashes (header_hash, aad_hash)
- Secure randomness: injected interface for tests (deterministic PRNG in tests)

### 1.2 Keys and chains (Signal-like)
State variables:
- RK: Root Key (32 bytes)
- DHs: our current ratchet keypair (priv,pub)
- DHr: their current ratchet public key
- CKs: sending chain key
- CKr: receiving chain key
Counters:
- Ns: messages sent in current sending chain
- Nr: messages received in current receiving chain
- PN: length of previous sending chain (for header)
- Epoch: DHRatchetCount, increments per DH ratchet event

Skipped-keys store:
- Skipped[(Epoch, Nr)] = MK, bounded by MaxSkip, plus Used bit.

Security goals:
- FS: message keys derived and then erased/consumed.
- PCS: after compromise, next DH ratchet restores secrecy once one honest message is exchanged.

---

## 2. Key schedule (domain-separated)

### 2.1 Root key update on DH ratchet
When DH ratchet occurs, compute:
- DH = X25519(DHsPriv, DHrPub)  (or X25519(newDHsPriv, DHrPub) depending on direction)
- (RK', CKr') = HKDF(RK, DH, info="ce.ratchet.rk.v1", out=64)
  - first 32 bytes -> RK'
  - next 32 bytes  -> CKr'

For send chain after generating new DHs:
- DH2 = X25519(newDHsPriv, DHrPub)
- (RK'', CKs') = HKDF(RK', DH2, info="ce.ratchet.rk.v1", out=64)
  - first 32 -> RK''
  - next 32  -> CKs'

NOTE: This matches standard Double Ratchet structure (two-stage when initiating a new sending chain),
but must be strictly controlled by QKeyRotation gating.

### 2.2 Message key derivation (symmetric ratchet)
From chain key CK:
- (CK_next, MK) = HKDF(CK, salt=nil, info="ce.ratchet.mk.v1", out=64)
  - first 32 -> CK_next
  - next  32 -> MK

Rules:
- MK is single-use. After encrypt/decrypt, it must be treated as consumed.
- CK advances exactly once per message number increment.

---

## 3. Message header and EnvelopeV2 integration

### 3.1 EnvelopeV2 fields (binding rules)
We reuse EnvelopeV2 and enforce **strict header/AAD binding**:
- EnvelopeV2 header MUST include ratchet header fields (below) in canonical form.
- The ratchet layer MUST:
  1) build canonical header bytes
  2) compute header_hash = SHA256(header_bytes)
  3) compute aad_hash = SHA256(aad_bytes)  (where aad_bytes are EnvelopeV2 AAD canonical bytes)
  4) build op_context = BuildOpContext(...)
  5) pass op_context into QKeyRotationV1 for gating/authorization

### 3.2 Ratchet header fields (no permanent identifiers)
Include the following fields (all ephemeral/session-scoped):
- epoch (u32): sender's DHRatchetCount
- pn (u32): sender's PN
- n (u32): sender's message number within current sending chain (Ns at send time)
- dhr_pub (32 bytes): sender's current DH ratchet public key (DHsPub)
- flags (u16): reserved (future: header key, multi-device, etc.)

Constraints:
- No long-lived sender IDs.
- The only “routing handle” is whatever the transport uses; ratchet does not add identifiers.

---

## 4. QKeyRotationV1 governance model

### 4.1 Why governance exists
Classic Double Ratchet assumes local state transition is always allowed.
CarthEdge requires:
- policy constraints (rate limits, step sequencing, recovery controls)
- introspection and reason codes
- explicit op_context binding to prevent cross-protocol or replayed operation authorization

### 4.2 Required QKR hooks (SDK surface)
We define three hooks and forbid direct state mutations outside these:

1) ratchet_step_send(state, envelope_header_bytes, aad_bytes) -> (mk, updated_state)
2) ratchet_step_recv(state, incoming_header_bytes, aad_bytes) -> (maybe_mk_source, updated_state)
3) decrypt_msg(state, incoming_envelope, aad_bytes) -> (plaintext, updated_state)

Governance rules:
- Every hook MUST:
  - compute (header_hash, aad_hash)
  - build op_context = canonical bytes
  - call QKeyRotationV1 to authorize the sensitive transition
  - if blocked, MUST fail deterministically with ErrPolicyBlocked and leave state unchanged
- Recovery path MUST be explicit:
  - QKR policy block may demand “forced recovery”, which locks state and forces a deterministic reset procedure.

### 4.3 Gating points (must be enforced)
- DH ratchet step (when DHr_pub changes) MUST be authorized.
- Advancing CKs/Ns (send chain) MUST be authorized.
- Advancing CKr/Nr (recv chain) MUST be authorized.
- Consuming skipped keys MUST be authorized.
- Accepting out-of-order messages within window MUST be authorized (policy may tighten).

---

## 5. Replay protection (explicit, testable)

### 5.1 Threat model
Relay (or attacker) can:
- replay old ciphertexts
- duplicate messages
- reorder messages
- delay messages

We must reject replays deterministically, offline.

### 5.2 Mechanisms
A message is uniquely identified (for replay purposes) by:
- (epoch, n, dhr_pub) as encoded in canonical header bytes.

Rules:
- If (epoch,n) corresponds to an already-consumed MK, reject with ErrReplay.
- If n < Nr in current receiving chain:
  - accept only if MK exists in Skipped[(epoch,n)] and Used=false
  - otherwise reject (ErrReplay or ErrDesync depending on context)
- If n > Nr:
  - derive and store skipped keys for Nr..(n-1), bounded by MaxSkip
  - then derive MK for n and set Nr = n+1
- Skipped key storage MUST be bounded and pruned deterministically (v0.3.2).

---

## 6. State machine (transitions + failure modes)

### 6.1 High-level states
- ACTIVE: normal operation
- LOCKED: policy-required lock (forced recovery pending)
- ERROR: transient classification (state remains ACTIVE but LastErr set for introspection)

### 6.2 Transition rules (recv side)
On incoming header H:
- Parse epoch_in, pn_in, n_in, dhr_pub_in
- If state.LOCKED -> fail ErrStateLocked
- If dhr_pub_in != state.DHrPub:
  - **DH ratchet required**
  - QKR authorize op_context(op=ratchet_step_recv, epoch=state.Epoch, Ns,Nr,...)
  - if authorized:
    - set PN = Ns
    - set Ns = 0, Nr = 0
    - set DHrPub = dhr_pub_in
    - derive new RK, CKr (and potentially CKs after local DHs refresh depending on direction in v0.3.1)
    - increment Epoch
  - else fail ErrPolicyBlocked (no state change)
- Then handle n_in relative to Nr with skipped-keys logic (authorized per step).

Failure modes (must map to stable ErrKind):
- ErrPolicyBlocked: QKR denies transition
- ErrReplay: duplicate or reused MK
- ErrDesync: message too far ahead, skipped-window overflow, or counter wrap
- ErrAADMismatch: canonical header/AAD mismatch (tamper)
- ErrCiphertextInvalid: AEAD open fails
- ErrInvariant: internal invariant violation (requires recovery path)

### 6.3 Transition rules (send side)
On send request:
- If LOCKED -> ErrStateLocked
- QKR authorize op_context(op=ratchet_step_send, epoch=Epoch, Ns,Nr,...)
- If authorized:
  - derive MK from CKs
  - increment Ns (reject wrap-around)
  - bind MK into EnvelopeV2 encryption
- If policy requires DH ratchet before send (e.g., after receiving new DHr):
  - send-side ratchet occurs under QKR control (v0.3.1).

---

## 7. Deterministic testing requirements (offline-first)
All tests MUST:
- run offline (no network, no time sleeps)
- use deterministic RNG injection
- validate explicit failure kinds (ErrKind), not fragile strings
- cover:
  - normal flow
  - replay attack
  - state desync
  - forced recovery via policy block

---

## 8. Open questions locked for v0.3.1+
- Header-key encryption (Signal “header keys”) is deferred; we keep fields canonical now.
- Multi-device / multi-session fanout is deferred.
- Exact QKR policy schema for ratchet operations (rate limits, max skip) finalized in v0.3.1.

