# CarthEdge v0.3.4 — Channel Primitives (FOUNDATION)

## Scope
Define a secure channel abstraction built on top of existing RatchetState.
This layer introduces **channels without permanent identifiers**, supporting
secure fan-out messaging via independent ratchets.

## Non-negotiables
- No permanent identifiers
- No global group keys
- Pair-wise ratchets only
- QKeyRotation governs all sensitive channel operations
- Offline-first, deterministic behavior

## Definitions

### ChannelId
A channel identifier is **derived**, not stored permanently.

ChannelId = H(
"carthedge/channel/v0.3.4" ||
sorted(member_ephemeral_ids) ||
channel_epoch
)

### ChannelMember
Each member is represented by:
- ephemeral member_id (32 bytes)
- associated RatchetState
- membership epoch

### ChannelState
ChannelState {
channel_id: [u8;32]
channel_epoch: u64
members: Map<MemberId, RatchetState>
policy_hash: [u8;32] // bound to QKR policy
}

## Operations (QKR-governed)

| Operation | op_name | op_context |
|---------|--------|------------|
| create channel | channel_create | channel_id |
| send message | channel_send | channel_id \|\| member_id |
| rotate channel | channel_rotate | channel_epoch |
| remove member | channel_remove | member_id |

## Security Properties
- Forward Secrecy per member
- Post-Compromise Safety via ratchet rotation
- No cross-member metadata leakage
- Replay protection via underlying ratchets

## Out of Scope
- UI / UX
- Optimized group sender keys
- Federation
