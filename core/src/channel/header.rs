use sha2::{Digest, Sha256};

use crate::types::MsgType;

/// ChannelHeader for broadcast/channel messaging.
/// No permanent identifiers allowed.
///
/// Canonical encoding:
/// [msg_type:1][epoch:8 LE][counter:8 LE][member_ix:4 LE]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelHeader {
    pub msg_type: MsgType,  // ChannelMsg
    pub epoch: u64,         // ratchet epoch (recovery increments)
    pub counter: u64,       // per-member sending counter
    pub member_ix: u32,     // index inside ChannelState.members (ephemeral role)
}

impl ChannelHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 8 + 8 + 4);
        out.push(self.msg_type as u8);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.counter.to_le_bytes());
        out.extend_from_slice(&self.member_ix.to_le_bytes());
        out
    }

    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"carthedge/v0.3.5/channel_header_hash");
        h.update(self.to_bytes());
        let d = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        out
    }
}
