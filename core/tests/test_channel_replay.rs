use carthedge_core::channel::{ChannelHeader, ChannelMember, ChannelState};
use carthedge_core::qkr_gate::AllowAllGate;
use carthedge_core::ratchet::RatchetState;
use carthedge_core::types::MsgType;

#[test]
fn channel_replay_detected() {
    let gate = AllowAllGate;
    let mut st = ChannelState::new_for_tests(vec![ChannelMember::new_for_tests(RatchetState::dummy())]);
    let mut sender = RatchetState::dummy();

    sender.step_send(&gate).unwrap();
    let mk = carthedge_core::ratchet::hkdf_expand_32(&sender.chain_key_send, b"carthedge/ratchet/mk");

    let header = ChannelHeader { msg_type: MsgType::ChannelMsg, epoch: 0, counter: 0, member_ix: 0 };
    let env = carthedge_core::envelope::EnvelopeV2::seal(
        MsgType::ChannelMsg, 0, header.to_bytes(), header.hash().to_vec(), &mk, b"hi"
    ).unwrap();

    // first receive ok
    st.recv_for_member(&gate, 0, &header, &env).unwrap();

    // second receive must be replay
    let err = st.recv_for_member(&gate, 0, &header, &env).unwrap_err();
    let s = format!("{:?}", err);
    assert!(s.contains("Replay") || s.contains("replay") || s.contains("ReplayDetected"));
}
