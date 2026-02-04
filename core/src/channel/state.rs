use std::collections::BTreeMap;

use crate::error::CoreError;
use crate::qkr_gate::QkrGate;
use crate::channel::member::{ChannelMember, MemberId};

pub struct ChannelState {
    pub channel_id: [u8;32],
    pub channel_epoch: u64,
    pub members: BTreeMap<MemberId, ChannelMember>,
}

impl ChannelState {
    pub fn new<G: QkrGate>(
        gate: &G,
        channel_id: [u8;32],
    ) -> Result<Self, CoreError> {
        let dec = gate.gate("channel_create", &channel_id)?;
        if !dec.allowed {
            return Err(CoreError::GateBlocked(dec.human));
        }

        Ok(Self {
            channel_id,
            channel_epoch: 0,
            members: BTreeMap::new(),
        })
    }

    pub fn add_member(
        &mut self,
        member: ChannelMember,
    ) {
        self.members.insert(member.member_id, member);
    }

    pub fn rotate<G: QkrGate>(
        &mut self,
        gate: &G,
    ) -> Result<(), CoreError> {
        let ctx = self.channel_epoch.to_le_bytes();
        let dec = gate.gate("channel_rotate", &ctx)?;
        if !dec.allowed {
            return Err(CoreError::GateBlocked(dec.human));
        }

        self.channel_epoch += 1;
        Ok(())
    }
}
