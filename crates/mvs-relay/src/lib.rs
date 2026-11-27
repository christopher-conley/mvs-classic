//! The relay (relay/): a program anyone may run that holds its players' lobbies, searches, invites and presence, the
//! links that carry their packets, the host cores of its queue and its hosted lobbies ([`hosted`]) and the referees
//! of their matches. [`core`] holds the rules, synchronous and on one owner; the sockets around it run on a
//! current-thread tokio runtime.

pub mod core;
pub mod hosted;
pub mod limits;
mod registry_link;
pub mod server;
