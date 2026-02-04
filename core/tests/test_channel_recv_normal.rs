use carthedge_core::channel::{ChannelHeader, ChannelMember, ChannelState};
use carthedge_core::qkr_gate::AllowAllGate;
use carthedge_core::ratchet::RatchetState;
use carthedge_core::types::MsgType;

#[test]
fn channel_recv_normal_roundtrip() {
    let gate = AllowAllGate;

    // one member channel
    let mut st = ChannelState::new_for_tests(vec![ChannelMember::new_for_tests(RatchetState::dummy())]);

    // simulate sender state separately (same initial state for deterministic test)
    let mut sender = RatchetState::dummy();

    // sender derives mk and increments counters
    sender.step_send(&gate).unwrap();
    let mk = carthedge_core::ratchet::hkdf_expand_32(&sender.chain_key_send, b"carthedge/ratchet/mk");

    let header = ChannelHeader {
        msg_type: MsgType::ChannelMsg,
        epoch: 0,
        counter: 0,
        member_ix: 0,
    };

    let env = carthedge_core::envelope::EnvelopeV2::seal(
        MsgType::ChannelMsg,
        0,
        header.to_bytes(),
        header.hash().to_vec(),
        &mk,
        b"hello",
    )
    .unwrap();

    let out = st.recv_for_member(&gate, 0, &header, &env).unwrap();
    assert_eq!(out, b"hello".to_vec());
}
