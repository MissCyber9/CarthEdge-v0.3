use carthedge_core::ratchet::RatchetState;
use carthedge_core::qkr_gate::AllowAllGate;

#[test]
fn ratchet_state_send_counter_monotone() {
    let gate = AllowAllGate;

    let mut state = RatchetState::new([0u8;32], [1u8;32], [2u8;32]);
    assert_eq!(state.send_counter, 0);

    state.step_send(&gate).unwrap();
    assert_eq!(state.send_counter, 1);
    assert_eq!(state.prev_send_counter, 0);

    state.step_send(&gate).unwrap();
    assert_eq!(state.send_counter, 2);
    assert_eq!(state.prev_send_counter, 1);
}

#[test]
fn ratchet_state_recv_counter_monotone() {
    let gate = AllowAllGate;

    let mut state = RatchetState::new([0u8;32], [1u8;32], [2u8;32]);
    assert_eq!(state.recv_counter, 0);

    state.step_recv(&gate).unwrap();
    assert_eq!(state.recv_counter, 1);

    state.step_recv(&gate).unwrap();
    assert_eq!(state.recv_counter, 2);
}
