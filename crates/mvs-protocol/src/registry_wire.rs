//! The registry link's wire: between a relay and the registry that tells it which other relays it may meet. The
//! relay dials the registry ([`REGISTRY_PORT`]) and keeps the link: it checks in with its address, versions and counts
//! ([`ToRegistry::CheckIn`]), beats every [`BEAT_MS`] with its counts, and hears back the relays it may meet as
//! changes: one listed or changed ([`FromRegistry::RelayUp`]), one gone ([`FromRegistry::RelayGone`]). The registry
//! keeps the counts to itself; a relay keeps one entry for each id. Messages are UTF-8 JSON `{ t, ... }`, field names
//! camelCase.
//!
//! The link's start has the relay wire's shape: hello (the relay's key, a nonce and an X25519 key of its own, `kx`) ->
//! challenge (the registry's key, nonce, `kx` and signature) -> prove (the relay's signature) -> welcome { id } or
//! refused { why }, both signatures over the relay wire's transcript ([`Transcript`]) behind this link's own contexts
//! ([`registry_handshake_bytes`]), so a signature made for the relay wire never passes here, nor one of this link's
//! there. Keys, nonces, `kx` and signatures are standard base64 with padding. The whole link is the port's own.

use crate::relay_wire::{Side, TRANSCRIPT_BYTES, Transcript};
use serde::{Deserialize, Serialize};

/// The link's version (a hello's and a challenge's `v`).
pub const REGISTRY_WIRE_VERSION: u32 = 1;
/// The registry's TCP port: below the relay's 7777, leaving the ports above it to the game (LAN's 7778).
pub const REGISTRY_PORT: u16 = 7776;
/// A relay's beat, and the silence after which the registry lets it go (ms). Unverified: the port's own numbers.
pub const BEAT_MS: f64 = 5000.0;
pub const SILENT_MS: f64 = 15000.0;
/// A link's start (hello to welcome) takes this long at the most, on both sides (ms).
pub const START_MS: f64 = 10000.0;
/// What each side's signature covers before the transcript (the NUL included): the registry's, then the relay's.
pub const SIGN_REGISTRY: &[u8] = b"mvs-registry-v1:registry\0";
pub const SIGN_MEMBER: &[u8] = b"mvs-registry-v1:relay\0";

/// The bytes one side signs in the link's start: its context ([`SIGN_REGISTRY`] / [`SIGN_MEMBER`]), then T
/// ([`Transcript::bytes`]), as [`crate::relay_wire::handshake_bytes`] has them for the relay wire. Side::Relay is the
/// registry's signature, Side::Client the dialing relay's.
pub fn registry_handshake_bytes(side: Side, t: &Transcript) -> Vec<u8> {
    let ctx = match side {
        Side::Relay => SIGN_REGISTRY,
        Side::Client => SIGN_MEMBER,
    };
    let mut out = Vec::with_capacity(ctx.len() + TRANSCRIPT_BYTES);
    out.extend_from_slice(ctx);
    out.extend_from_slice(&t.bytes());
    out
}

/// A relay's load: its players and matches now, and the most of each it takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    pub players: u32,
    pub max_players: u32,
    pub matches: u32,
    pub max_matches: u32,
}

/// One relay in a [`FromRegistry::RelayUp`]: its id, the IPv4 `a.b.c.d:port` the registry verified it at, its name
/// if it has one, and whether it is on the registry's allow list (a ping target and a host candidate).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayEntry {
    pub id: String,
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub approved: bool,
}

/// What a relay sends the registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "camelCase")]
pub enum ToRegistry {
    /// The start's first message: `v` is [`REGISTRY_WIRE_VERSION`].
    Hello { v: u32, key: String, nonce: String, kx: String },
    /// The relay's signature ([`SIGN_MEMBER`]).
    Prove { sig: String },
    /// The address the relay is reached at (`host:port`), its [`crate::relay_wire::RELAY_WIRE_VERSION`] (`wire`), its
    /// [`crate::version::PROTOCOL`] (`proto`) and its load.
    CheckIn { address: String, wire: u32, proto: u32, counts: Counts },
    /// Every [`BEAT_MS`]: the relay's load now.
    Beat { counts: Counts },
}

/// What the registry sends a relay.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "camelCase")]
pub enum FromRegistry {
    /// The answer to a hello: the registry's key, nonce and `kx`, and its signature ([`SIGN_REGISTRY`]).
    Challenge {
        v: u32,
        key: String,
        nonce: String,
        kx: String,
        sig: String,
    },
    /// The start is done: the relay's id.
    Welcome {
        id: String,
    },
    Refused {
        why: String,
    },
    /// The answer to each beat: what tells a relay its registry is still there.
    Beat {},
    /// A relay this one may meet (same protocol, itself left out) is listed, or its entry changed: the receiver keeps
    /// the last entry sent for each id. At its own listing a relay hears one of these for each relay already there.
    RelayUp {
        relay: RelayEntry,
    },
    /// A relay sent in a [`FromRegistry::RelayUp`] is gone.
    RelayGone {
        id: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay_wire::{self, NONCE_BYTES};
    use serde_json::json;

    fn transcript() -> Transcript {
        Transcript {
            client_key: [1; 32],
            relay_key: [2; 32],
            client_nonce: [3; NONCE_BYTES],
            relay_nonce: [4; NONCE_BYTES],
            client_kx: [5; 32],
            relay_kx: [6; 32],
        }
    }

    #[test]
    fn the_signing_contexts_are_the_links_own() {
        let t = transcript();
        let registry = registry_handshake_bytes(Side::Relay, &t);
        let member = registry_handshake_bytes(Side::Client, &t);
        assert!(registry.starts_with(SIGN_REGISTRY));
        assert!(registry.ends_with(&t.bytes()));
        assert_ne!(registry, relay_wire::handshake_bytes(Side::Relay, &t));
        assert_ne!(registry, member);
        assert!(member.starts_with(SIGN_MEMBER));
    }

    #[test]
    fn messages_keep_their_wire_names() {
        let counts = Counts { players: 1, max_players: 500, matches: 0, max_matches: 250 };
        let check_in = ToRegistry::CheckIn { address: "a:1".into(), wire: 7, proto: 31, counts };
        assert_eq!(
            serde_json::to_value(check_in).unwrap(),
            json!({"t":"checkIn","address":"a:1","wire":7,"proto":31,"counts":{"players":1,"maxPlayers":500,"matches":0,"maxMatches":250}})
        );
        let relay = RelayEntry { id: "r1".into(), address: "1.2.3.4:7777".into(), name: None, approved: false };
        assert_eq!(
            serde_json::to_value(FromRegistry::RelayUp { relay }).unwrap(),
            json!({"t":"relayUp","relay":{"id":"r1","address":"1.2.3.4:7777","approved":false}}),
            "no name is left out"
        );
    }

    #[test]
    fn a_relay_gone_is_its_id() {
        assert_eq!(
            serde_json::to_value(FromRegistry::RelayGone { id: "r1".into() }).unwrap(),
            json!({"t":"relayGone","id":"r1"})
        );
    }

    #[test]
    fn an_unknown_message_does_not_read() {
        assert!(serde_json::from_value::<FromRegistry>(json!({"t":"nope"})).is_err());
    }

    #[test]
    fn a_beat_answer_is_bare() {
        assert_eq!(serde_json::to_value(FromRegistry::Beat {}).unwrap(), json!({"t":"beat"}));
    }
}
