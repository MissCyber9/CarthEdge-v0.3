use sha2::{Digest, Sha256};

use crate::types::MsgType;

/// Minimal header for ratchet messages.
/// No permanent identifiers allowed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RatchetHeader {
    pub msg_type: MsgType,      // RatchetMsg
    pub counter: u64,           // monotone per sending chain
    pub prev_counter: u64,      // for future out-of-order handling
    pub dh_pub: Option<[u8; 32]>, // future DH-ratchet (None for v0.2.2.2)
}

impl RatchetHeader {
    /// Canonical bytes: use a stable manual encoding to avoid serde format ambiguity.
    /// Format:
    /// [msg_type:1][counter:8 LE][prev_counter:8 LE][dh_flag:1][dh_pub:32?]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 8 + 8 + 1 + 32);
        out.push(self.msg_type as u8);
        out.extend_from_slice(&self.counter.to_le_bytes());
        out.extend_from_slice(&self.prev_counter.to_le_bytes());
        match self.dh_pub {
            None => out.push(0u8),
            Some(pk) => {
                out.push(1u8);
                out.extend_from_slice(&pk);
            }
        }
        out
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"carthedge/v0.2.2.2/header_hash");
        h.update(self.to_bytes());
        let d = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        out
    }
}
