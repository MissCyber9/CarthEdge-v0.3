use carthedge_core::channel::{ChannelHeader, ChannelMember, ChannelState};
use carthedge_core::qkr_gate::AllowAllGate;
use carthedge_core::ratchet::RatchetState;
use carthedge_core::types::MsgType;

#[test]
fn channel_epoch_mismatch_forces_recovery() {
    let gate = AllowAllGate;
    let mut st = ChannelState::new_for_tests(vec![ChannelMember::new_for_tests(RatchetState::dummy())]);

    // epoch mismatch
    let header = ChannelHeader { msg_type: MsgType::ChannelMsg, epoch: 9, counter: 0, member_ix: 0 };

    // dummy envelope placeholders (will fail earlier on envelope mismatch if not well-formed)
    let mk = [0u8; 32];
    let env = carthedge_core::envelope::EnvelopeV2::seal(
        MsgType::ChannelMsg, 0, header.to_bytes(), header.hash().to_vec(), &mk, b"x"
    ).unwrap();

    let err = st.recv_for_member(&gate, 0, &header, &env).unwrap_err();
    let s = format!("{:?}", err);
    assert!(s.contains("ForcedRecovery") || s.contains("recovery") || s.contains("Forced"));
}
