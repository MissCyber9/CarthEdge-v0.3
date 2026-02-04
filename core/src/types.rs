/// Minimal shared types for CarthEdge core (v0.3.x)
/// No permanent identifiers.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReasonCode(pub u32);

#[derive(Clone, Debug)]
pub struct GateDecision {
    pub allowed: bool,
    pub reason_codes: Vec<ReasonCode>,
    pub human: String,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgType {
    RatchetMsg = 1,
    ChannelMsg = 2,
}
