use crate::error::CoreError;
use crate::qkr_gate::QkrGate;
use crate::ratchet::{DhKeyPair, SkippedKeyStore, RatchetStatus};

/// RatchetState: minimal Signal-like symmetric ratchet core (v0.3.x)
/// - Governance-first: all sensitive evolution gated through QkrGate
/// - Offline-first: deterministic behavior for tests
///
/// NOTE:
/// Integration tests under `core/tests/` compile this crate as a normal dependency,
/// therefore helpers used by those tests MUST be available without `cfg(test)`.
pub struct RatchetState {
    pub status: RatchetStatus,

    pub root_key: [u8; 32],

    pub chain_key_send: [u8; 32],
    pub chain_key_recv: [u8; 32],

    pub send_counter: u64,
    pub recv_counter: u64,
    pub prev_send_counter: u64,

    pub dh_local: DhKeyPair,
    pub dh_remote: Option<[u8; 32]>,

    pub epoch: u64,
    pub skipped: SkippedKeyStore,
}

impl RatchetState {
    /// Canonical constructor after handshake-derived keys.
    pub fn new(root: [u8; 32], ck_s: [u8; 32], ck_r: [u8; 32]) -> Self {
        Self {
            status: RatchetStatus::Running,
            root_key: root,
            chain_key_send: ck_s,
            chain_key_recv: ck_r,
            send_counter: 0,
            recv_counter: 0,
            prev_send_counter: 0,
            dh_local: DhKeyPair::generate(),
            dh_remote: None,
            epoch: 0,
            skipped: SkippedKeyStore::new(64),
        }
    }

    /// Deterministic constructor used by offline integration tests.
    /// This is safe: it creates a syntactically valid state; governance still applies at runtime.
    pub fn dummy() -> Self {
        Self::new([0u8; 32], [0u8; 32], [0u8; 32])
    }

    /// Lock the ratchet (no cryptographic progress allowed).
    pub fn lock(&mut self) {
        self.status = RatchetStatus::Locked;
    }

    /// Force recovery through governance.
    pub fn force_recover<G: QkrGate>(&mut self, gate: &G) -> Result<(), CoreError> {
        let dec = gate.gate("ratchet_recover", b"force")?;
        if !dec.allowed {
            return Err(CoreError::GateBlocked(dec.human));
        }
        self.status = RatchetStatus::Running;
        self.epoch = self.epoch.wrapping_add(1);
        Ok(())
    }

    /// Derive next message key from send chain (Signal-style).
    ///
    /// Governance:
    /// - op_name = "ratchet_msg_key"
    /// - op_context = chain_key_send
    pub fn ratchet_next_message_key<G: QkrGate>(
        &mut self,
        gate: &G,
    ) -> Result<[u8; 32], CoreError> {
        if self.status != RatchetStatus::Running {
            return Err(CoreError::RatchetLocked);
        }

        let dec = gate.gate("ratchet_msg_key", &self.chain_key_send)?;
        if !dec.allowed {
            return Err(CoreError::GateBlocked(dec.human));
        }

        let mk = crate::ratchet::kdf::hkdf_expand_32(
            &self.chain_key_send,
            b"carthedge/ratchet/mk",
        );
        let ck_next = crate::ratchet::kdf::hkdf_expand_32(
            &self.chain_key_send,
            b"carthedge/ratchet/ck",
        );

        self.chain_key_send = ck_next;
        self.send_counter = self.send_counter.wrapping_add(1);

        Ok(mk)
    }

    /// Minimal receive-chain progress for v0.3.x (no DH-ratchet here).
    ///
    /// Governance:
    /// - op_name = "ratchet_step_recv"
    /// - op_context = chain_key_recv
    pub fn ratchet_step_recv<G: QkrGate>(&mut self, gate: &G) -> Result<(), CoreError> {
        if self.status != RatchetStatus::Running {
            return Err(CoreError::RatchetLocked);
        }

        let dec = gate.gate("ratchet_step_recv", &self.chain_key_recv)?;
        if !dec.allowed {
            return Err(CoreError::GateBlocked(dec.human));
        }

        self.chain_key_recv = crate::ratchet::kdf::hkdf_expand_32(
            &self.chain_key_recv,
            b"carthedge/ratchet/ck",
        );
        self.recv_counter = self.recv_counter.wrapping_add(1);
        Ok(())
    }

    /// Backward-compatible alias for older integration tests.
    /// Semantics: "advance send chain once" (governed).
    pub fn step_send<G: QkrGate>(&mut self, gate: &G) -> Result<(), CoreError> {
        if self.status != RatchetStatus::Running {
            return Err(CoreError::RatchetLocked);
        }

        // Monotone invariant expected by tests:
        // after one step_send(), send_counter == previous + 1
        self.prev_send_counter = self.send_counter;
        self.send_counter = self.send_counter.wrapping_add(1);

        // Governance gate binds op_context to current send chain state.
        let dec = gate.gate("ratchet_msg_key", &self.chain_key_send)?;
        if !dec.allowed {
            // rollback counters to keep state stable on deny
            self.send_counter = self.prev_send_counter;
            return Err(CoreError::GateBlocked(dec.human));
        }

        // Advance send chain once (derive next chain key)
        self.chain_key_send = crate::ratchet::kdf::hkdf_expand_32(
            &self.chain_key_send,
            b"carthedge/ratchet/ck",
        );

        Ok(())
    }

    /// Backward-compatible alias for older integration tests.
    /// Semantics: "advance recv chain once" (governed).
    pub fn step_recv<G: QkrGate>(&mut self, gate: &G) -> Result<(), CoreError> {
        self.ratchet_step_recv(gate)
    }
}
