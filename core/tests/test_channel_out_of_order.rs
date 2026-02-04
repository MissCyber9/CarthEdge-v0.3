use carthedge_core::channel::{ChannelHeader, ChannelMember, ChannelState};
use carthedge_core::qkr_gate::AllowAllGate;
use carthedge_core::ratchet::RatchetState;
use carthedge_core::types::MsgType;

#[test]
fn channel_out_of_order_within_window() {
    let gate = AllowAllGate;
    let mut st = ChannelState::new_for_tests(vec![ChannelMember::new_for_tests(RatchetState::dummy())]);
    let mut sender = RatchetState::dummy();

    // produce msg0 and msg1 keys (deterministic)
    sender.step_send(&gate).unwrap();
    let mk0 = carthedge_core::ratchet::hkdf_expand_32(&sender.chain_key_send, b"carthedge/ratchet/mk");

    sender.step_send(&gate).unwrap();
    let mk1 = carthedge_core::ratchet::hkdf_expand_32(&sender.chain_key_send, b"carthedge/ratchet/mk");

    let h1 = ChannelHeader { msg_type: MsgType::ChannelMsg, epoch: 0, counter: 1, member_ix: 0 };
    let e1 = carthedge_core::envelope::EnvelopeV2::seal(
        MsgType::ChannelMsg, 0, h1.to_bytes(), h1.hash().to_vec(), &mk1, b"m1"
    ).unwrap();

    // Receive message 1 first (should store skipped for 0)
    let out1 = st.recv_for_member(&gate, 0, &h1, &e1).unwrap();
    assert_eq!(out1, b"m1".to_vec());

    let h0 = ChannelHeader { msg_type: MsgType::ChannelMsg, epoch: 0, counter: 0, member_ix: 0 };
    let e0 = carthedge_core::envelope::EnvelopeV2::seal(
        MsgType::ChannelMsg, 0, h0.to_bytes(), h0.hash().to_vec(), &mk0, b"m0"
    ).unwrap();

    // Receive message 0 later (should use skipped store)
    let out0 = st.recv_for_member(&gate, 0, &h0, &e0).unwrap();
    assert_eq!(out0, b"m0".to_vec());
}
