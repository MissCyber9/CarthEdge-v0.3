use carthedge_core::channel::ChannelState;
use carthedge_core::qkr_gate::AllowAllGate;

#[test]
fn channel_create_and_rotate() {
    let gate = AllowAllGate;
    let mut ch = ChannelState::new();
    assert_eq!(ch.epoch, 0);

    ch.rotate(&gate).unwrap();
    assert_eq!(ch.epoch, 1);
}
