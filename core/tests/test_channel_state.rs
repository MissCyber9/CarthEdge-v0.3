use carthedge_core::channel::ChannelState;
use carthedge_core::qkr_gate::AllowAllGate;

#[test]
fn channel_create_and_rotate() {
    let gate = AllowAllGate;
    let channel_id = [7u8;32];

    let mut ch = ChannelState::new(&gate, channel_id).unwrap();
    assert_eq!(ch.channel_epoch, 0);

    ch.rotate(&gate).unwrap();
    assert_eq!(ch.channel_epoch, 1);
}
