use crate::ratchet::RatchetState;

pub type MemberId = [u8; 32];

pub struct ChannelMember {
    pub member_id: MemberId,
    pub ratchet: RatchetState,
}

impl ChannelMember {
    pub fn new(member_id: MemberId, ratchet: RatchetState) -> Self {
        Self { member_id, ratchet }
    }

    /// Test helper (deterministic)
    pub fn new_for_tests(ratchet: RatchetState) -> Self {
        Self { member_id: [0u8; 32], ratchet }
    }
}
