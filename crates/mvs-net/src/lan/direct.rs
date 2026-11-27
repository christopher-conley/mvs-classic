//! The direct host and its joiners: a custom lobby served by
//! this app itself, and the join of another app's by its code.
//!   the host   a relay core of its own per hosted lobby, its own player on it in process ([`LocalBackend`]), and a
//!              listener for the others (mvs-relay's server with that core and the install's key, so its key is the one
//!              the code names, and its traffic is sealed as a relay's: `mvs_protocol::relay_seal`), on the setting's
//!              port or the next free one, TCP and UDP. The core and the listener run on a thread of their own (a
//!              current-thread runtime), the game's calls go there as commands. The
//!              others may join and leave the host's lobby and send packets; they make no lobby, search none and
//!              invite no one (the server's guest rules), so the listener is no relay for strangers on the network.
//!              Closed with the lobby.
//!   the join   the code read, then a relay client to each of its addresses at once ([`RelayClient::connect_with`]
//!              with the code's fingerprint as host key): the first whose host proves that key signs in, the others are
//!              closed before they sign in (the start's claim); each try has the client's start deadline.
//!
//! Without `loopback` the host listens on every IPv4 address (0.0.0.0) and the code names the PC's addresses. Every run
//! of the checks uses `loopback` (127.0.0.1 alone, the code names it).

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use mvs_relay::hosted::HostedOptions;
use mvs_relay::limits::RelayLimits;
use mvs_relay::server::{Guest, Options, Relay, start_relay};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use super::announce::{LogFn, system_interfaces};
use super::direct_code::{
    DIRECT_ADDRESSES, DirectCode, DirectWhy, Interfaces, Local, decode_direct_code, encode_direct_code, local_address,
    pick_addresses,
};
use super::local::{LCmd, LEvent, LocalBackend, LocalPlayer};
use crate::codes::CodeMakeWhy;
use crate::fail::{HOST_CLOSED, NetFail};
use crate::link::relay::key::{KeyError, RelayKey, key_fingerprint, key_id};
use crate::link::relay::{ClientOptions, RelayClient, RelayError, StartWith};
use crate::pending::Pending;

/// The ports tried from the setting's on, when it is taken. Unverified: the port's own number.
pub const PORT_TRIES: u16 = 20;

/// A player on the listener in no lobby of the host for this long (from its welcome, or from its leave or kick) is
/// dropped. Unverified: the port's own number (a join follows the welcome at once; a kicked player's game leaves).
pub const JOIN_WITHIN_MS: f64 = 15000.0;

pub struct DirectHostOptions {
    pub key_file: PathBuf,
    /// The hosted lobby's most players.
    pub max: u32,
    /// Tests: how long a player may be in no lobby ([`JOIN_WITHIN_MS`] by default).
    pub join_within_ms: Option<f64>,
    /// The setting's port: the first one tried.
    pub port: u16,
    /// Tests: listen on 127.0.0.1 alone, and the code names it.
    pub loopback: bool,
    pub log: Option<LogFn>,
    /// This PC's interfaces (tests); the system's by default.
    pub interfaces: Option<fn() -> Interfaces>,
}

/// Why a direct host did not start. The menus word it; the `Display` is the log's words.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum HostStartWhy {
    /// This install's relay key could not be read: its file and the system's reason.
    #[error("the relay key {file} could not be read: {text}")]
    KeyRead { file: String, text: String },
    /// This install's relay key could not be made or set aside: its file and the reason.
    #[error("the relay key {file} could not be written: {text}")]
    KeyWrite { file: String, text: String },
    /// This PC has no address on a local network.
    #[error("this PC is on no network (it has no address on a local network)")]
    NoNetwork,
    /// The listener could not start (its thread or runtime, a port's bind): the system's reason, if any.
    #[error("it cannot listen{}", listen_reason(.text))]
    CannotListen { text: Option<String> },
    /// Every port from the setting's on (`PORT_TRIES` of them) is held.
    #[error("ports {first} to {last} are all in use")]
    PortsInUse { first: u16, last: u16 },
    /// The listener's thread ended before it said whether it listens.
    #[error("the direct host's thread stopped")]
    ThreadStopped,
    /// The host's core refused its own player: the core's reason.
    #[error("the host's own player was refused: {why}")]
    OwnRefused {
        #[serde(rename = "text")]
        why: NetFail,
    },
}

/// ": <reason>" when there is one.
fn listen_reason(text: &Option<String>) -> String {
    text.as_ref().map_or_else(String::new, |t| format!(": {t}"))
}

impl From<KeyError> for HostStartWhy {
    fn from(e: KeyError) -> HostStartWhy {
        match e {
            KeyError::Read(f, e) => HostStartWhy::KeyRead { file: f.display().to_string(), text: e.to_string() },
            KeyError::Write(f, text) => HostStartWhy::KeyWrite { file: f.display().to_string(), text },
        }
    }
}

/// A running direct host: its listener thread, which ends with `close`.
pub struct DirectHost {
    /// The host's own player on its core; taken out by the service (the code and the close do not need it).
    pub backend: Option<LocalBackend>,
    /// The port it listens on, and the addresses its codes name (the likeliest first).
    pub port: u16,
    pub addresses: Vec<String>,
    /// The host's own id, and its key's fingerprint.
    pub me: String,
    fingerprint: String,
    loopback: bool,
    cmds: UnboundedSender<LCmd>,
    thread: Option<JoinHandle<()>>,
}

impl DirectHost {
    /// The code of a lobby of its core; Err when its values cannot be written in one.
    pub fn code(&self, lobby: &str) -> Result<String, CodeMakeWhy> {
        let n = self.addresses.len().min(DIRECT_ADDRESSES);
        let c = DirectCode {
            addresses: self.addresses[..n].to_vec(),
            port: self.port,
            fingerprint: self.fingerprint.clone(),
            lobby: lobby.to_owned(),
        };
        encode_direct_code(&c, self.loopback).map_err(|e| CodeMakeWhy::of_direct(e, self.port))
    }

    /// Closes the host and returns at once: the own player is out of the core without a sign-out, and the listener
    /// thread closes the listener (every other player told, after the relay's linger) and ends on its own.
    pub fn close(&mut self) {
        let _ = self.cmds.send(LCmd::Close);
        self.thread.take();
    }
}

impl Drop for DirectHost {
    fn drop(&mut self) {
        self.close();
    }
}

/// This PC's addresses on a local network, the likeliest first (empty: on no network); `loopback`: 127.0.0.1 alone.
pub fn local_addresses(loopback: bool, nets: Option<fn() -> Interfaces>) -> Vec<String> {
    pick_addresses(&nets.map_or_else(system_interfaces, |f| f()), loopback)
}

/// The listener's limits: the lobby's players and a few more (a player rejoining before its old link is gone, a
/// stranger), two connections from one address; with `loopback` (tests: every player on 127.0.0.1) the address limit
/// is the players'. Unverified: the port's own numbers.
fn host_limits(max: u32, loopback: bool) -> RelayLimits {
    let max = f64::from(max);
    RelayLimits {
        players: 2.0 * max,
        connections_per_address: if loopback { 2.0 * max } else { 2.0 },
        members_per_lobby: max,
        lobbies_per_player: 1.0,
        ..RelayLimits::default()
    }
}

/// What the listener thread starts from.
struct Setup {
    key_file: PathBuf,
    me: String,
    max: u32,
    join_within_ms: f64,
    port: u16,
    loopback: bool,
    log: Option<LogFn>,
    interfaces: Option<fn() -> Interfaces>,
}

/// [`open_direct_host`] on a thread of its own: the result is polled.
pub fn begin_host(o: DirectHostOptions) -> Pending<Result<DirectHost, HostStartWhy>> {
    Pending::start(move |_| open_direct_host(o))
}

/// Starts a direct host (it returns once the listener is bound, a few ms; the service calls [`begin_host`]): Err when
/// this PC has no network address (unless `loopback`), the key cannot be read, or no port from the setting's on is free
/// ([`PORT_TRIES`] of them).
pub fn open_direct_host(o: DirectHostOptions) -> Result<DirectHost, HostStartWhy> {
    let key = RelayKey::load(&o.key_file)?;
    let addresses = local_addresses(o.loopback, o.interfaces);
    if addresses.is_empty() {
        return Err(HostStartWhy::NoNetwork);
    }
    let me = key.id().to_owned();
    let (cmd_tx, cmd_rx) = unbounded_channel::<LCmd>();
    let (ev_tx, ev_rx) = mpsc::channel::<LEvent>();
    let (ready_tx, ready_rx) = mpsc::channel::<Result<u16, HostStartWhy>>();
    let setup = Setup {
        key_file: o.key_file.clone(),
        me: me.clone(),
        max: o.max,
        join_within_ms: o.join_within_ms.unwrap_or(JOIN_WITHIN_MS),
        port: o.port,
        loopback: o.loopback,
        log: o.log,
        interfaces: o.interfaces,
    };
    let thread = std::thread::Builder::new()
        .name("mvs-direct-host".to_owned())
        .spawn(move || host_thread(setup, &ready_tx, cmd_rx, ev_tx))
        .map_err(|e| HostStartWhy::CannotListen { text: Some(e.to_string()) })?;
    let port = match ready_rx.recv() {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => {
            let _ = thread.join();
            return Err(e);
        }
        Err(_) => {
            let _ = thread.join();
            return Err(HostStartWhy::ThreadStopped);
        }
    };
    Ok(DirectHost {
        backend: Some(LocalBackend::new(me.clone(), cmd_tx.clone(), ev_rx)),
        port,
        addresses,
        me,
        fingerprint: key_fingerprint(key.raw()),
        loopback: o.loopback,
        cmds: cmd_tx,
        thread: Some(thread),
    })
}

/// The listener thread: a current-thread runtime with the relay's listener, the core's own player, and the commands.
fn host_thread(
    s: Setup,
    ready: &mpsc::Sender<Result<u16, HostStartWhy>>,
    cmds: UnboundedReceiver<LCmd>,
    events: mpsc::Sender<LEvent>,
) {
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = ready.send(Err(HostStartWhy::CannotListen { text: Some(e.to_string()) }));
            return;
        }
    };
    let local = tokio::task::LocalSet::new();
    rt.block_on(local.run_until(host_run(s, ready, cmds, events)));
}

async fn host_run(
    s: Setup,
    ready: &mpsc::Sender<Result<u16, HostStartWhy>>,
    mut cmds: UnboundedReceiver<LCmd>,
    events: mpsc::Sender<LEvent>,
) {
    let top = s.port.saturating_add(PORT_TRIES - 1);
    let mut last: Option<std::io::Error> = None;
    let mut relay: Option<Relay> = None;
    let log: Option<Arc<Mutex<LogFn>>> = s.log.map(|l| Arc::new(Mutex::new(l)));
    // (the networks of this PC at the host's start: a guest on one of them, a virtual network's too, is let in)
    let local = Local::of(&s.interfaces.map_or_else(system_interfaces, |f| f()), s.loopback);
    for p in s.port..=top {
        let loopback = s.loopback;
        let o = Options {
            port: p,
            // Deviation: see the module's.
            host: if loopback { "127.0.0.1" } else { "0.0.0.0" }.to_owned(),
            key_file: Some(s.key_file.clone()),
            limits: host_limits(s.max, loopback),
            log: log.clone().map(|l| -> mvs_relay::server::LogLine {
                Box::new(move |line| {
                    if let Ok(mut f) = l.lock() {
                        f(line);
                    }
                })
            }),
            now: None,
            accept: Some(Box::new({
                let local = local.clone();
                move |a: &IpAddr| local_address(&a.to_string(), &local)
            })),
            guest: Some(Guest { host: s.me.clone(), join_within_ms: s.join_within_ms }),
            // (its lobby's host core; no queue)
            hosted: Some(HostedOptions::system(false)),
            // (its guests join by its direct code: a short code would name the release's relay)
            shorts: false,
            registry: None,
        };
        match start_relay(o) {
            Ok(r) => {
                relay = Some(r);
                break;
            }
            Err(e) => {
                // (a port another program holds, or one Windows keeps for itself: the next)
                let again = matches!(e.kind(), std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied);
                last = Some(e);
                if !again {
                    break;
                }
            }
        }
    }
    let Some(relay) = relay else {
        let why = match &last {
            Some(e) if matches!(e.kind(), std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied) => {
                HostStartWhy::PortsInUse { first: s.port, last: top }
            }
            Some(e) => HostStartWhy::CannotListen { text: Some(e.to_string()) },
            None => HostStartWhy::CannotListen { text: None },
        };
        let _ = ready.send(Err(why));
        return;
    };
    let player = LocalPlayer { events: events.clone() };
    let joined = relay.with_core(|core, now| core.join(&s.me, "this PC", Box::new(player), now));
    let session = match joined {
        Ok((session, _resumed)) => session,
        Err(e) => {
            let _ = ready.send(Err(HostStartWhy::OwnRefused { why: NetFail::of(&e) }));
            relay.close().await;
            return;
        }
    };
    let _ = ready.send(Ok(relay.port));
    let mut in_core = true;
    // (a command is awaited, not polled for: it runs the moment it is sent)
    loop {
        match cmds.recv().await {
            Some(LCmd::Request { tag, req }) => {
                if !in_core {
                    if let Some(tag) = tag {
                        let _ = events.send(LEvent::Answer { tag, result: Err(HOST_CLOSED.to_owned()) });
                    }
                    continue;
                }
                let r = relay.with_core(|core, now| core.request(&session, &req, now));
                // (after the messages the call made, which the core handed to the own player as it ran)
                if let Some(tag) = tag {
                    let _ = events.send(LEvent::Answer { tag, result: r.map_err(str::to_owned) });
                }
            }
            Some(LCmd::Send { to, channel, bytes }) => {
                if in_core {
                    relay.with_core(|core, now| core.packet(&session, channel, &to, &bytes, now));
                }
            }
            Some(LCmd::ClosePeer(to)) => {
                if in_core {
                    relay.with_core(|core, now| core.close_peer(&session, &to, now));
                }
            }
            Some(LCmd::Leave) => {
                if in_core {
                    in_core = false;
                    relay.with_core(|core, now| core.leave(&session, now));
                }
            }
            Some(LCmd::Close) => {
                // (on purpose: the own player's backend ends without a sign-out)
                let _ = events.send(LEvent::Closed);
                break;
            }
            None => break,
        }
    }
    if in_core {
        relay.with_core(|core, now| core.leave(&session, now));
    }
    relay.close().await;
}

pub struct DirectJoinOptions {
    pub key_file: PathBuf,
    /// Tests: a code may name 127.x.
    pub loopback: bool,
    /// The hello's app, the client's waits and its clock.
    pub client: ClientOptions,
    /// Set to end the join: it fails as cancelled.
    pub cancel: Option<Arc<AtomicBool>>,
}

/// A direct code joined: the signed-in client, the host core's lobby the code names and the host's own id.
pub struct DirectLink {
    pub client: RelayClient,
    /// The code's address the link was made to (`address:port`).
    pub at: String,
    pub lobby: String,
    pub host: String,
    pub code: DirectCode,
}

/// A start's failure after the host proved its key that the host itself gave (the client's start), not the network's.
fn host_answered(w: &str) -> bool {
    [
        "the relay refused",
        "the relay speaks wire version",
        "the relay named this player",
        "the relay sent a bad",
        "the relay answered out of turn",
        "the relay did not prove",
    ]
    .iter()
    .any(|p| w.starts_with(p))
}

/// Why a join by a direct code failed: a code; the words a player reads are the menus'. The payload text of a variant
/// is the log's (the client's own words), never shown.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectJoinWhy {
    /// The code does not read (the decoder's refusals: mistyped, another version, outside a local
    /// network).
    Code(DirectWhy),
    /// The install's key cannot be read or made.
    Key(String),
    /// 'cancelled': the join was ended from outside.
    Cancelled,
    /// 'the host refused the join: <why>': the host answered a try (refused, another wire version, a bad proof) with
    /// this reason.
    HostRefused(String),
    /// An address answered, but its host's key is not the one the code names.
    WrongHost,
    /// 'the host could not be reached: a network error (<each address>:<port>: <why>; ...)': no address answered; each
    /// one's address with port and the reason of its failure.
    Unreachable(Vec<(String, String)>),
}

impl DirectJoinWhy {
    /// The log's words, for the log and the tests alone.
    pub fn log_text(&self) -> String {
        match self {
            DirectJoinWhy::Code(w) => w.log_text(),
            DirectJoinWhy::Key(e) => e.clone(),
            DirectJoinWhy::Cancelled => "cancelled".to_owned(),
            DirectJoinWhy::HostRefused(w) => format!("the host refused the join: {w}"),
            DirectJoinWhy::WrongHost => "the host is not the one its code names".to_owned(),
            DirectJoinWhy::Unreachable(each) => {
                let each: Vec<String> = each.iter().map(|(a, w)| format!("{a}: {w}")).collect();
                format!("the host could not be reached: a network error ({})", each.join("; "))
            }
        }
    }
}

/// What the tries of one join share.
struct Race {
    claimed: Option<usize>,
    refused: String,
    held: HashSet<usize>,
}

/// [`join_direct`] on a thread of its own: the result is polled, and its cancel ends the join (the `cancel` of the
/// options is replaced by it).
pub fn begin_join(text: String, o: DirectJoinOptions) -> Pending<Result<DirectLink, DirectJoinWhy>> {
    Pending::start(move |cancel| join_direct(&text, DirectJoinOptions { cancel: Some(cancel), ..o }))
}

/// Reads a direct code and signs in to its host, waiting for it (the service calls [`begin_join`]) (the first of its
/// addresses whose host proves the code's key); Err with why not: a mistyped code, no address answered (each one's
/// reason), the host not the code's.
///
/// The race: each address tried at once; the first whose host proves the key claims the sign-in, and the others stop at
/// their claim (unsigned in). A claimed try that then fails on the network lets the addresses that stopped for it be
/// tried again; one the host answered (refused, another wire version) ends the join with that reason.
pub fn join_direct(text: &str, o: DirectJoinOptions) -> Result<DirectLink, DirectJoinWhy> {
    let code = decode_direct_code(text, &Local::of(&system_interfaces(), o.loopback)).map_err(DirectJoinWhy::Code)?;
    let key = RelayKey::load(&o.key_file).map_err(|e| DirectJoinWhy::Key(e.to_string()))?;
    let cancelled = || o.cancel.as_ref().is_some_and(|c| c.load(Ordering::Relaxed));
    if cancelled() {
        return Err(DirectJoinWhy::Cancelled);
    }
    let race = Arc::new(Mutex::new(Race { claimed: None, refused: String::new(), held: HashSet::new() }));
    let (tx, rx) = mpsc::channel::<(usize, Result<RelayClient, RelayError>)>();
    let tries: Arc<Mutex<Vec<Arc<AtomicBool>>>> = Arc::new(Mutex::new(Vec::new()));
    let mut running = 0usize;
    let attempt = |i: usize, running: &mut usize| {
        *running += 1;
        let stop = Arc::new(AtomicBool::new(false));
        if cancelled() {
            stop.store(true, Ordering::Relaxed);
        }
        tries.lock().expect("tries").push(stop.clone());
        let address = format!("{}:{}", code.addresses[i], code.port);
        let (key, client, tx) = (key.clone(), o.client.clone(), tx.clone());
        let claim_race = race.clone();
        let overall = o.cancel.clone();
        let x = StartWith {
            host_key: Some(code.fingerprint.clone()),
            relay_id: None,
            claim: Some(Arc::new(move || {
                let mut r = claim_race.lock().expect("race");
                if overall.as_ref().is_some_and(|c| c.load(Ordering::Relaxed))
                    || !r.refused.is_empty()
                    || r.claimed.is_some()
                {
                    if r.claimed.is_some() {
                        r.held.insert(i);
                    }
                    return false;
                }
                r.claimed = Some(i);
                true
            })),
            cancel: Some(stop),
        };
        std::thread::spawn(move || {
            let r = RelayClient::connect_with(&address, &key, &client, &x);
            let _ = tx.send((i, r));
        });
    };
    let cancel_all = || {
        for t in tries.lock().expect("tries").iter() {
            t.store(true, Ordering::Relaxed);
        }
    };
    for i in 0..code.addresses.len() {
        attempt(i, &mut running);
    }
    let mut why: Vec<Option<String>> = vec![None; code.addresses.len()];
    let (link, at) = loop {
        // (a cancel from outside ends the tries; their results follow)
        if cancelled() {
            cancel_all();
        }
        let (i, r) = match rx.recv_timeout(Duration::from_millis(20)) {
            Ok(x) => x,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(DirectJoinWhy::Cancelled),
        };
        running -= 1;
        match r {
            Ok(client) => {
                cancel_all();
                break (client, format!("{}:{}", code.addresses[i], code.port));
            }
            Err(e) => {
                let mut again: Vec<usize> = Vec::new();
                {
                    let mut st = race.lock().expect("race");
                    if !st.held.contains(&i) {
                        why[i] = Some(e.to_string());
                    }
                    if st.claimed == Some(i) {
                        st.claimed = None;
                        let w = why[i].clone().unwrap_or_default();
                        if host_answered(&w) {
                            st.refused = w;
                        } else if !cancelled() {
                            // (the host proved its key there, then the network failed: the others again)
                            again = st.held.drain().collect();
                            again.sort_unstable();
                        }
                    }
                }
                for k in again {
                    attempt(k, &mut running);
                }
                if running > 0 {
                    continue;
                }
                if cancelled() {
                    return Err(DirectJoinWhy::Cancelled);
                }
                let refused = race.lock().expect("race").refused.clone();
                if !refused.is_empty() {
                    return Err(DirectJoinWhy::HostRefused(refused));
                }
                if why.iter().flatten().any(|w| w.contains("not the one its code names")) {
                    return Err(DirectJoinWhy::WrongHost);
                }
                let tries = code
                    .addresses
                    .iter()
                    .enumerate()
                    .map(|(k, a)| {
                        (format!("{a}:{}", code.port), why[k].clone().unwrap_or_else(|| "not tried".to_owned()))
                    })
                    .collect();
                return Err(DirectJoinWhy::Unreachable(tries));
            }
        }
    };
    if cancelled() {
        link.shutdown();
        return Err(DirectJoinWhy::Cancelled);
    }
    let host = B64.decode(link.relay().0).map(|r| key_id(&r)).unwrap_or_default();
    Ok(DirectLink { client: link, at, lobby: code.lobby.clone(), host, code })
}
