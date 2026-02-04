
use sha2::{Digest, Sha256};

use crate::envelope::EnvelopeV2;
use crate::error::CoreError;
use crate::qkr_gate::QkrGate;
use crate::ratchet::hkdf_expand_32;
use crate::types::MsgType;

use super::{ChannelHeader, ChannelState};

fn digest2(label: &[u8], a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(label);
    h.update(a);
    h.update(b);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

impl ChannelState {
    /// Receive + decrypt for member `member_ix`.
    ///
    /// Non-negotiables:
    /// - No permanent identifiers.
    /// - Governance: gate decrypt_msg with op_context = header_hash.
    /// - Replay protection: explicit + testable via SkippedKeyStore.
    /// - Epoch mismatch => ForcedRecovery (no silent desync).
    pub fn recv_for_member<G: QkrGate>(
        &mut self,
        gate: &G,
        member_ix: u32,
        header: &ChannelHeader,
        env: &EnvelopeV2,
    ) -> Result<Vec<u8>, CoreError> {
        if header.msg_type != MsgType::ChannelMsg {
            return Err(CoreError::InvalidEnvelope);
        }
        if header.member_ix != member_ix {
            return Err(CoreError::InvalidEnvelope);
        }

        let hh = header.hash();

        // Governance gate: bind decryption to header hash (AAD binding)
        let dec = gate.gate("decrypt_msg", &hh)?;
        if !dec.allowed {
            return Err(CoreError::GateBlocked(dec.human));
        }

        // Member lookup: ChannelState.members is a BTreeMap keyed by usize
let member = self
    .members
    .get_mut(header.member_ix as usize)
     .ok_or(CoreError::InvalidEnvelope)?;


        // Epoch mismatch => forced recovery path (policy block)
        if header.epoch != member.ratchet.epoch {
            return Err(CoreError::ForcedRecovery);
        }

        // Bind header->envelope
        let hb = header.to_bytes();
        if env.header != hb {
            return Err(CoreError::InvalidEnvelope);
        }
        if env.aad != hh.to_vec() {
            return Err(CoreError::InvalidEnvelope);
        }

        let expected = member.ratchet.recv_counter;

        // Old/out-of-order (counter < expected): must use skipped store or be replay
        if header.counter < expected {
            let key_id = digest2(
                b"carthedge/v0.3.5/skipped_key_id",
                &header.epoch.to_le_bytes(),
                &header.counter.to_le_bytes(),
            );

            let d2 = gate.gate("skipped_key_use", &key_id)?;
            if !d2.allowed {
                return Err(CoreError::GateBlocked(d2.human));
            }

            if let Some(mk) = member.ratchet.skipped.take(header.counter) {
                return env.open(&mk);
            }
            return Err(CoreError::ReplayDetected);
        }

        // Future/out-of-order (counter > expected): derive and store skipped keys up to counter-1
        if header.counter > expected {
            let mut c = expected;
            while c < header.counter {
                // Advance recv chain once (QKR-gated inside ratchet_step_recv)
                member.ratchet.ratchet_step_recv(gate)?;

                // Deterministic mk derived from the current recv chain state
                let mk = hkdf_expand_32(&member.ratchet.chain_key_recv, b"carthedge/ratchet/mk");

                member
                    .ratchet
                    .skipped
                    .put(c, mk)
                    .map_err(|_| CoreError::SkippedStoreError)?;

                c = c.wrapping_add(1);
            }
        }

        // Normal: header.counter == expected
        member.ratchet.ratchet_step_recv(gate)?;
        let mk = hkdf_expand_32(&member.ratchet.chain_key_recv, b"carthedge/ratchet/mk");
        env.open(&mk)
    }
}
