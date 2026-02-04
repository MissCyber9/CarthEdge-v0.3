use crate::channel::ChannelMember;
use crate::error::CoreError;
use crate::qkr_gate::QkrGate;

#[derive(Default)]
pub struct ChannelState {
    pub members: Vec<ChannelMember>,
    pub epoch: u64,
}

impl ChannelState {
    pub fn new() -> Self {
        Self { members: Vec::new(), epoch: 0 }
    }

    /// Add a member at the next index.
    /// The index is the authoritative `member_ix` in v0.3.
    pub fn add_member(&mut self, member: ChannelMember) -> u32 {
        let ix = self.members.len() as u32;
        self.members.push(member);
        ix
    }

    pub fn member_mut(&mut self, ix: u32) -> Result<&mut ChannelMember, CoreError> {
        self.members.get_mut(ix as usize).ok_or(CoreError::InvalidEnvelope)
    }

    /// Channel-level epoch rotation (foundation for recovery + policy-driven resync).
    /// Governance: op_name="channel_rotate", op_context = epoch LE bytes.
    pub fn rotate<G: QkrGate>(&mut self, gate: &G) -> Result<(), CoreError> {
        let ctx = self.epoch.to_le_bytes();
        let dec = gate.gate("channel_rotate", &ctx)?;
        if !dec.allowed {
            return Err(CoreError::GateBlocked(dec.human));
        }
        self.epoch = self.epoch.wrapping_add(1);
        Ok(())
    }

    /// Test helper
    pub fn new_for_tests(members: Vec<ChannelMember>) -> Self {
        Self { members, epoch: 0 }
    }
}
