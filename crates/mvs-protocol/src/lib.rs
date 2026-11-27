//! What the game, the host core and the relay share (the wire's types): the host core's messages and the
//! server's choices, the custom lobby's rules, the queue's rules, a match's set-up, packets and referee, the match
//! record, the profile data, the relay's wire, a session's P2P framing and the protocol's version. No sockets and no
//! sim: the callers carry the bytes and pass the clock in.

pub mod chat;
pub mod loadout;
pub mod lobby_listing;
pub mod lobby_rules;
pub mod match_wire;
pub mod messages;
pub mod names;
pub mod online;
pub mod p2p_frame;
pub mod path;
pub mod profile;
pub mod queue_rules;
pub mod record;
pub mod referee;
pub mod registry_wire;
pub mod relay_seal;
pub mod relay_wire;
pub mod roster;
pub mod setup;
pub mod version;

#[doc(hidden)]
pub mod vectors;
