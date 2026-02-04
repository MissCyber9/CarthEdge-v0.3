use crate::error::CoreError;
use crate::qkr_gate::QkrGate;
use crate::ratchet::{DhKeyPair, SkippedKeyStore};
use crate::ratchet::hkdf_extract_and_expand_96;

pub struct RatchetState {
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
    pub fn new(root: [u8;32], ck_s: [u8;32], ck_r: [u8;32]) -> Self {
        Self {
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

    /// Perform a DH ratchet step (Signal-style).
    /// Governance: op_name = "ratchet_dh_step", op_context = peer_pub
    pub fn step_send<G: QkrGate>(&mut self, gate: &G) -> Result<(), CoreError> {
        let dec = gate.gate("ratchet_step_send", &self.chain_key_send)?;
        if !dec.allowed {
            return Err(CoreError::GateBlocked(dec.human));
        }
        self.prev_send_counter = self.send_counter;
        self.send_counter = self.send_counter.wrapping_add(1);
        Ok(())
    }

    pub fn step_recv<G: QkrGate>(&mut self, gate: &G) -> Result<(), CoreError> {
        let dec = gate.gate("ratchet_step_recv", &self.chain_key_recv)?;
        if !dec.allowed {
            return Err(CoreError::GateBlocked(dec.human));
        }
        self.recv_counter = self.recv_counter.wrapping_add(1);
        Ok(())
    }

    pub fn dh_ratchet<G: QkrGate>(
        &mut self,
        gate: &G,
        peer_pub: [u8;32],
    ) -> Result<(), CoreError> {
        let dec = gate.gate("ratchet_dh_step", &peer_pub)?;
        if !dec.allowed {
            return Err(CoreError::GateBlocked(dec.human));
        }

        let peer = x25519_dalek::PublicKey::from(peer_pub);
        let dh_secret = self.dh_local.dh_once(&peer);

        let okm = hkdf_extract_and_expand_96(
            &self.root_key,
            &dh_secret,
            b"carthedge/v0.3/dh_ratchet",
        );

        self.root_key.copy_from_slice(&okm[0..32]);
        self.chain_key_recv.copy_from_slice(&okm[32..64]);
        self.chain_key_send.copy_from_slice(&okm[64..96]);

        self.prev_send_counter = self.send_counter;
        self.send_counter = 0;
        self.recv_counter = 0;

        self.dh_local.regenerate();
        self.dh_remote = Some(peer_pub);
        self.epoch += 1;

        Ok(())
    }
}
