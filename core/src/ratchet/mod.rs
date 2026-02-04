use sha2::{Digest, Sha256};

use crate::error::CoreError;
use crate::envelope::EnvelopeV2;
use crate::qkr_gate::QkrGate;
use crate::types::GateDecision;
use crate::types::MsgType;

mod kdf;
mod header;
mod dh;
mod skipped;
mod state;
pub use kdf::*;
pub use header::*;
pub use dh::*;
pub use skipped::*;
pub use state::*;

#[derive(Clone, Debug)]
pub struct SessionKeys {
    pub root_key: [u8; 32],
    pub chain_key_send: [u8; 32],
    pub chain_key_recv: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct MessageKeys {
    pub msg_key: [u8; 32],
    pub next_chain_key: [u8; 32],
}

fn enforce_gate(decision: GateDecision) -> Result<(), CoreError> {
    if decision.allowed {
        Ok(())
    } else {
        let msg = if !decision.human.is_empty() {
            decision.human.clone()
        } else {
            format!("{:?}", decision.reason_codes)
        };
        Err(CoreError::GateBlocked(msg))
    }
}

/// Transcript hash binds the session keys to the handshake artifacts.
/// Important: DO NOT include permanent identifiers. Only ephemeral handshake material + protocol version.
pub fn transcript_hash(e_i: &[u8; 32], e_r: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"carthedge/v0.2.2/transcript");
    h.update(e_i);
    h.update(e_r);
    let out = h.finalize();
    let mut th = [0u8; 32];
    th.copy_from_slice(&out);
    th
}

/// Derive root_key + (send, recv) chain keys from handshake shared secret and transcript hash.
/// Governance: gate op_name "ratchet_derive_session_keys" using op_context = transcript_hash.
pub fn derive_session_keys<G: QkrGate>(
    gate: &G,
    handshake_shared_secret: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> Result<SessionKeys, CoreError> {
    enforce_gate(gate.gate("ratchet_derive_session_keys", transcript_hash)?)?;

    // HKDF output: 96 bytes => root_key || ck_send || ck_recv
    let okm = hkdf_extract_and_expand_96(
        transcript_hash,
        handshake_shared_secret,
        b"carthedge/v0.2.2/session_keys",
    );

    let mut rk = [0u8; 32];
    let mut cks = [0u8; 32];
    let mut ckr = [0u8; 32];
    rk.copy_from_slice(&okm[0..32]);
    cks.copy_from_slice(&okm[32..64]);
    ckr.copy_from_slice(&okm[64..96]);

    Ok(SessionKeys { root_key: rk, chain_key_send: cks, chain_key_recv: ckr })
}

/// Advance one symmetric chain step (no DH-ratchet yet).
/// Governance: gate "ratchet_step" with op_context = current chain_key.
pub fn ratchet_step<G: QkrGate>(gate: &G, chain_key: &[u8; 32]) -> Result<MessageKeys, CoreError> {
    {
        let mut h = Sha256::new();
        h.update(b"carthedge/v0.2.2.1/ratchet_step");
        h.update(chain_key);
        let digest = h.finalize();
        enforce_gate(gate.gate("ratchet_step", &digest)?)?;
    }

    // msg_key and next_chain_key derived from current chain_key
    let msg_key = hkdf_expand_32(chain_key, b"carthedge/v0.2.2/msg_key");
    let next_chain_key = hkdf_expand_32(chain_key, b"carthedge/v0.2.2/chain_key");
    Ok(MessageKeys { msg_key, next_chain_key })
}

/// Seal a ratchet message with EnvelopeV2 using AAD = header_hash.
/// Governance: gate op_name "send_msg" with op_context = header_hash.
pub fn seal_ratchet_msg<G: QkrGate>(
    gate: &G,
    header: &RatchetHeader,
    msg_key: &[u8; 32],
    plaintext: &[u8],
) -> Result<EnvelopeV2, CoreError> {
    let hh = header.hash();
    enforce_gate(gate.gate("send_msg", &hh)?)?;
    EnvelopeV2::seal(MsgType::RatchetMsg, 0u16, header.to_bytes(), hh.to_vec(), msg_key, plaintext)
}

/// Open a ratchet message with EnvelopeV2 using AAD = header_hash.
/// Governance: gate op_name "decrypt_msg" with op_context = header_hash.
pub fn open_ratchet_msg<G: QkrGate>(
    gate: &G,
    header: &RatchetHeader,
    msg_key: &[u8; 32],
    env: &EnvelopeV2,
) -> Result<Vec<u8>, CoreError> {
    let hh = header.hash();
    enforce_gate(gate.gate("decrypt_msg", &hh)?)?;
    // Bind header -> envelope: AAD must match header_hash, and header bytes must match too.
    let hb = header.to_bytes();
    if env.aad != hh.to_vec() {
        return Err(CoreError::InvalidEnvelope);
    }
    if env.header != hb {
        return Err(CoreError::InvalidEnvelope);
    }

    env.open(msg_key)
}
