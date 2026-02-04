use crate::ratchet::RatchetState;

pub type MemberId = [u8; 32];

pub struct ChannelMember {
    pub member_id: MemberId,
    pub ratchet: RatchetState,
}
