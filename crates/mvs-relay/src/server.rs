//! A relay on a port: the TCP connections and the UDP sockets of `mvs_protocol::relay_wire`, each
//! signed-in connection a player of a [`Core`]. The handshake, the frames, keepalive, the per-connection limits and the
//! peer handles are here; the lobbies and links are the core's. Everything runs on one thread (a tokio current-thread
//! runtime and a `LocalSet`): [`start_relay`] is called inside a `LocalSet`.
//!
//! Encodings: the JSON fields key, nonce, sig and token are standard base64 (with padding) of their raw bytes: a key is
//! the 32-byte raw Ed25519 public key, a signature the 64-byte raw one, a nonce NONCE_BYTES, the token TOKEN_BYTES. A
//! player's id is 'r' + the first 32 hex digits of the SHA-256 of its raw public key; the relay's own id the same of
//! its key. The relay's key file is PKCS#8 PEM.
//!
//! A client's text (its hello's fields, ids, requests) is never put in a refusal or a log line; a panic while one
//! connection's bytes are handled closes that connection, never the program.

use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::hash::{BuildHasher, RandomState};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::rc::Rc;
use std::task::Poll;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::{DecodePaddingMode, general_purpose::STANDARD};
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use indexmap::IndexMap;
use mvs_protocol::relay_seal::{
    DatagramOpener, FrameOpener, KX_BYTES, KxSecret, MAX_SEALED_DATAGRAM, SealedReader, TAG_BYTES, TxSeal,
    datagram_token, derive, shared, split,
};
use mvs_protocol::relay_wire::{
    FT_DATA, FT_JSON, FT_MATCH, Frame, FrameReader, FrameTooLong, MAX_FRAME, MAX_PEER_HANDLES, NONCE_BYTES,
    RELAY_WIRE_VERSION, ServerMessage, Side, TOKEN_BYTES, Transcript, UDP_FRESH_MS, UDP_LATE_MS, UDP_MATCH, UDP_PROBE,
    UDP_PROBE_ACK, UDP_PROBE_MS, bad_public_key, handshake_bytes, json_frame, normal_address, read_json, read_packet,
    read_udp_body,
};
use serde_json::{Map, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::core::{Core, CorePlayer, REFEREE_PUMP_MS, Session, Taken};
use crate::hosted::HostedOptions;
use crate::limits::{RelayLimits, TokenBucket, address_group, relay_limits};
use crate::registry_link::{self, Kept, Link, counts_of};
use mvs_protocol::registry_wire::RelayEntry;

/// How often the silent connections are looked for (ms).
const SWEEP_MS: u64 = 1000;
/// A refused connection is closed this long after its refused { why }, if the other side has not closed it (ms).
const LINGER_MS: u64 = 2000;
/// A channel-1 packet taken one way (TCP or UDP) and again the other within this long (ms) is one packet sent both
/// ways (a client whose UDP acknowledgements are late sends both): taken once. Deviation: the port's own bound.
const BOTH_WAYS_MS: f64 = UDP_PROBE_MS + UDP_LATE_MS;
/// The channel-1 packets each way remembers for that, at most. Deviation: the port's own bound.
const BOTH_WAYS_KEPT: usize = 256;

/// The relay's clock (ms, monotonic).
pub type Clock = Rc<dyn Fn() -> f64>;
/// One log line's taker (`Options::log`).
pub type LogLine = Box<dyn FnMut(&str)>;
/// Where the relay's log lines go.
pub type Log = Rc<RefCell<LogLine>>;

fn say_log(log: &Log, line: &str) {
    (log.borrow_mut())(line);
}

/// Base64 as Node's Buffer reads it: padding or none, trailing bits taken.
const LENIENT: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

/// `unb64`: base64 of exactly `N` bytes, else `None`.
fn unb64<const N: usize>(v: Option<&Value>) -> Option<[u8; N]> {
    let s = v?.as_str()?;
    if s.len() > 4 * N.div_ceil(3) {
        return None;
    }
    let body = s.trim_end_matches('=');
    if s.len() - body.len() > 2 || !body.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/') {
        return None;
    }
    // (Node's Buffer stops at a lone trailing character; a length that is no base64 one is no N bytes either way)
    LENIENT.decode(body).ok()?.try_into().ok()
}

/// `keyId`: the id of a raw public key (the wire's).
pub use mvs_protocol::relay_wire::key_id;

/// `loadKey`: the relay's key: read from `file`, made and written there when it is not there, or for this run only.
pub fn load_key(file: Option<&Path>) -> io::Result<SigningKey> {
    if let Some(f) = file
        && f.exists()
    {
        let pem = std::fs::read_to_string(f)?;
        return SigningKey::from_pkcs8_pem(&pem)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", f.display())));
    }
    let mut secret = [0u8; 32];
    rand::fill(&mut secret);
    let key = SigningKey::from_bytes(&secret);
    if let Some(f) = file {
        let pem = key.to_pkcs8_pem(LineEnding::LF).map_err(|e| io::Error::other(e.to_string()))?;
        write_private(f, pem.as_bytes())?;
    }
    Ok(key)
}

#[cfg(unix)]
fn write_private(f: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(f)?.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private(f: &Path, bytes: &[u8]) -> io::Result<()> {
    std::fs::write(f, bytes)
}

/// Runs a task of the relay: a panic in it that no guard caught ends the program with code 1, logged, as an uncaught
/// exception does (for a service manager to start it again); a relay that went on would be half broken.
fn spawn(log: &Log, f: impl Future<Output = ()> + 'static) -> JoinHandle<()> {
    tokio::task::spawn_local(Fatal { log: log.clone(), f: Box::pin(f) })
}

struct Fatal<F> {
    log: Log,
    f: std::pin::Pin<Box<F>>,
}

impl<F: Future<Output = ()>> Future for Fatal<F> {
    type Output = ();
    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<()> {
        match catch_unwind(AssertUnwindSafe(|| self.f.as_mut().poll(cx))) {
            Ok(p) => p,
            Err(_) => {
                if let Ok(mut l) = self.log.try_borrow_mut() {
                    l("uncaught panic; stopping");
                }
                std::process::exit(1);
            }
        }
    }
}

/// The JSON text as JSON.parse reads it, for serde_json. Deviation: a lone surrogate escape (which JavaScript keeps in
/// its string, and a Rust string cannot hold) becomes U+FFFD; a number past f64's range (JavaScript's Infinity) becomes
/// +-f64::MAX, which every check that refuses Infinity refuses too (`crate::core::finite`).
fn js_json(b: &[u8]) -> Cow<'_, [u8]> {
    let mut out: Vec<u8> = Vec::new();
    let mut last = 0;
    let swap = |out: &mut Vec<u8>, from: usize, to: usize, with: &[u8], last: &mut usize| {
        out.extend_from_slice(&b[*last..from]);
        out.extend_from_slice(with);
        *last = to;
    };
    let hex4 = |at: usize| -> Option<u32> {
        let h = b.get(at..at + 4)?;
        u32::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok()
    };
    let (mut i, mut text) = (0, false);
    while i < b.len() {
        let c = b[i];
        if text {
            match c {
                b'"' => text = false,
                b'\\' if b.get(i + 1) == Some(&b'u') => {
                    match hex4(i + 2) {
                        Some(0xD800..=0xDBFF)
                            if b.get(i + 6..i + 8) == Some(b"\\u") && matches!(hex4(i + 8), Some(0xDC00..=0xDFFF)) =>
                        {
                            i += 12;
                        }
                        Some(0xD800..=0xDFFF) => {
                            swap(&mut out, i, i + 6, b"\\uFFFD", &mut last);
                            i += 6;
                        }
                        _ => i += 2,
                    }
                    continue;
                }
                b'\\' => i += 1,
                _ => {}
            }
            i += 1;
            continue;
        }
        if c == b'"' {
            text = true;
        } else if c == b'-' || c.is_ascii_digit() {
            let start = i;
            while i < b.len() && matches!(b[i], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-') {
                i += 1;
            }
            let n = std::str::from_utf8(&b[start..i]).ok().and_then(|t| t.parse::<f64>().ok());
            if let Some(n) = n.filter(|n| n.is_infinite()) {
                let with: &[u8] = if n < 0.0 { b"-1.7976931348623157e308" } else { b"1.7976931348623157e308" };
                swap(&mut out, start, i, with, &mut last);
            }
            continue;
        }
        i += 1;
    }
    if last == 0 {
        return Cow::Borrowed(b);
    }
    out.extend_from_slice(&b[last..]);
    Cow::Owned(out)
}

/// `plain`: an address as one text (an IPv4 one without its ::ffff: head).
fn plain(a: &IpAddr) -> String {
    normal_address(&a.to_string()).unwrap_or_else(|| "?".into())
}

/// JavaScript's `.length` of a string.
fn js_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// What a relay is started with (`startRelay`'s options).
pub struct Options {
    /// The port for TCP and UDP; 0 picks one.
    pub port: u16,
    /// The address to listen on: empty for all of this PC's (IPv4 and IPv6). Deviation: an IP literal only (Node also
    /// resolves a name).
    pub host: String,
    pub key_file: Option<PathBuf>,
    pub limits: RelayLimits,
    pub log: Option<LogLine>,
    /// The clock of the limits and silences (ms, monotonic): the time since the start unless given.
    pub now: Option<Clock>,
    /// Which peer addresses are taken: another's TCP connection is closed at once, before its hello, and its UDP
    /// datagrams are ignored. All, unless given (a direct host takes its network's only). It gets the peer's
    /// IP, not the raw socket text (`::ffff:a.b.c.d` for an IPv4 client).
    pub accept: Option<Accept>,
    /// A direct host's rules for the players on this listener; the host's own
    /// player joins the core in process (`Relay::with_core`) and is not under them.
    pub guest: Option<Guest>,
    /// The host cores it runs: by default a queue core and the lobbies made with `host` (a direct host's: no queue);
    /// None: none.
    pub hosted: Option<HostedOptions>,
    /// Its hosted lobbies get a short code (`relay_wire::Created::short`): true unless given (a direct host's: false).
    pub shorts: bool,
    /// The registry it checks in to, on a link of its own: none by default, and then it opens no socket for one.
    pub registry: Option<RegistryOptions>,
}

/// A registry the relay checks in to (`Options::registry`).
#[derive(Clone, Debug, PartialEq)]
pub struct RegistryOptions {
    /// The registry's `host:port`, dialed as `relay_wire::parse_address` reads it (the config reader writes its
    /// port, `registry_wire::REGISTRY_PORT` when the config names none).
    pub address: String,
    /// The id the registry's key must have.
    pub id: String,
    /// The address players reach this relay at (`host:port`), sent in the check-in as given.
    pub public: String,
    /// The config's `afterMs` (ms): read and kept; nothing in the relay acts on it.
    pub after_ms: f64,
    /// The beat, the silence, a start's time and the first and longest wait before a new dial (ms): BEAT_MS,
    /// SILENT_MS, START_MS, 2000 and 60000.
    pub beat_ms: f64,
    pub silent_ms: f64,
    pub start_ms: f64,
    pub retry_ms: (f64, f64),
}

impl RegistryOptions {
    /// A registry at `address` whose key's id is `id`, this relay reached at `public`; the times are the defaults.
    pub fn new(address: &str, id: &str, public: &str) -> RegistryOptions {
        RegistryOptions {
            address: address.to_owned(),
            id: id.to_owned(),
            public: public.to_owned(),
            after_ms: 20000.0,
            beat_ms: mvs_protocol::registry_wire::BEAT_MS,
            silent_ms: mvs_protocol::registry_wire::SILENT_MS,
            start_ms: mvs_protocol::registry_wire::START_MS,
            retry_ms: (2000.0, 60000.0),
        }
    }
}

impl Default for Options {
    fn default() -> Options {
        Options {
            port: 0,
            host: String::new(),
            key_file: None,
            limits: RelayLimits::default(),
            log: None,
            now: None,
            accept: None,
            guest: None,
            hosted: Some(HostedOptions::system(true)),
            shorts: true,
            registry: None,
        }
    }
}

/// The rules of a direct host's listener: its players may join, leave and (the core lets only an
/// owner) kick, and send packets; they make no lobby, search none, list none and invite no one. The host's own id is
/// the host's alone: a connection under it is refused. A player in no lobby of the host for `join_within_ms` (from its
/// welcome, or from its leave or kick) is dropped.
#[derive(Clone, Debug)]
pub struct Guest {
    /// The host's own player's id.
    pub host: String,
    pub join_within_ms: f64,
}

/// The requests a direct host's guests may make.
const GUEST_OPS: [&str; 3] = ["join", "leave", "kick"];

/// `Options::accept`.
pub type Accept = Box<dyn Fn(&IpAddr) -> bool>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Hello,
    Prove,
    In,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Close {
    Open,
    /// Write what is held, then end the stream (the reader still runs until the other side closes or the linger).
    End,
    /// At once.
    Destroy,
}

/// A UDP socket: tokio's to wait for datagrams, a clone of it to send. (tokio's try_send_to refuses until it has seen
/// the socket writable, which a socket that only sends now and then never shows; a datagram is sent or lost at once.)
struct Udp {
    recv: UdpSocket,
    send: std::net::UdpSocket,
}

/// A connection's reader of the client's frames: plain until its prove is taken, sealed from the next frame on.
enum Reader {
    Plain(FrameReader),
    Sealed(SealedReader),
}

impl Reader {
    #[allow(clippy::should_implement_trait, reason = "a reader fed between calls, not an iterator")]
    fn next(&mut self) -> Option<Frame> {
        match self {
            Reader::Plain(r) => r.next(),
            Reader::Sealed(r) => r.next(),
        }
    }

    fn feed(&mut self, chunk: &[u8]) {
        match self {
            Reader::Plain(r) => r.feed(chunk),
            Reader::Sealed(r) => r.feed(chunk),
        }
    }

    /// Why the stream cannot be read on, if it cannot: a plain frame's length out of range, or a sealed frame that
    /// does not open (or whose length is out of range).
    fn bad(&self) -> Option<&'static str> {
        match self {
            Reader::Plain(r) => r.bad.then_some("frame too long"),
            Reader::Sealed(r) => r.bad.then_some("bad seal"),
        }
    }

    /// Bytes held for a frame not yet complete, and how many more than limits.frame_bytes a whole frame's bytes may
    /// be (its length, and a sealed frame's tag).
    fn pending(&self) -> (usize, usize) {
        match self {
            Reader::Plain(r) => (r.pending(), 4),
            Reader::Sealed(r) => (r.pending(), 4 + TAG_BYTES),
        }
    }
}

/// Appends one frame of type `ty` whose body is `parts` to the connection's bytes out: sealed once the challenge is
/// sent, plain before. Err when the body is too long for a frame, or the sealing's counter is spent.
fn put_frame(c: &mut Conn, ty: u8, parts: &[&[u8]]) -> Result<(), FrameTooLong> {
    if let Some(tx) = c.tx.as_mut() {
        return tx.frame_into(&mut c.out, ty, parts);
    }
    let body: usize = parts.iter().map(|p| p.len()).sum();
    if body + 1 > MAX_FRAME {
        return Err(FrameTooLong);
    }
    c.out.extend_from_slice(&u32::try_from(body + 1).map_err(|_| FrameTooLong)?.to_be_bytes());
    c.out.push(ty);
    for p in parts {
        c.out.extend_from_slice(p);
    }
    Ok(())
}

/// A client's UDP address, from its last probe (and that probe's flag).
struct UdpPeer {
    sock: Rc<Udp>,
    addr: SocketAddr,
    at: f64,
    heard: bool,
}

/// One TCP connection's state: its handshake, then its player.
struct Conn {
    /// Its IP address (normal_address), for the log and the UDP checks.
    address: String,
    /// What the per-address limit counts it by.
    group: String,
    reader: Reader,
    stage: Stage,
    heard: f64,
    control: TokenBucket,
    client_key: Option<VerifyingKey>,
    /// The start's transcript, once the challenge is sent.
    transcript: Option<Transcript>,
    /// What the relay sends with (relay_seal), from the challenge on: every frame after the challenge is sealed.
    tx: Option<TxSeal>,
    /// What the client's frames are opened with once its prove is taken (the reader's from then on).
    opener: Option<FrameOpener>,
    /// What the client's datagrams are opened with, from the challenge on.
    datagrams: Option<DatagramOpener>,
    id: String,
    session: Option<Session>,
    token: Option<[u8; TOKEN_BYTES]>,
    /// The client's live handles and the peer each names (and back); a new one must be above every one before.
    in_handles: HashMap<u32, String>,
    in_by_id: HashMap<String, u32>,
    last_in: u32,
    /// The live handles this relay names its peers by to the client; never a number twice.
    out_handles: HashMap<String, u32>,
    next_handle: u32,
    udp: Option<UdpPeer>,
    /// Bytes not yet handed to the writer.
    out: Vec<u8>,
    /// Bytes the writer holds, not yet taken by the socket (with `out`, Node's `writableLength`).
    flight: usize,
    close: Close,
    /// (a direct host's guest) The lobbies it is in, as the host's lobbies have told it.
    lobbies: indexmap::IndexSet<String>,
    /// The hello's count of channel-0 data frames the client took on its seat (None: a fresh sign-in).
    got: Option<u64>,
    /// The channel-1 packets lately taken by TCP (0) and by UDP (1): a hash of the handle and bytes, and when.
    both_ways: [VecDeque<(u64, f64)>; 2],
}

/// A connection: its state and the wakers of its writer and reader.
struct ConnCell {
    cid: u64,
    c: RefCell<Conn>,
    /// The writer has bytes or a close to see.
    wake: Notify,
    /// The reader stops (the connection is destroyed).
    kill: Notify,
    /// Its writer (aborted at the destroy: one blocked on a client that reads nothing frees the socket), its hello
    /// timer (cleared at leaveCore) and its refusal's linger (cleared at the end).
    writer: RefCell<Option<JoinHandle<()>>>,
    hello: RefCell<Option<JoinHandle<()>>>,
    linger: RefCell<Option<JoinHandle<()>>>,
    /// (a direct host's guest) its timer for being in no lobby.
    watch: RefCell<Option<JoinHandle<()>>>,
}

/// What every connection shares, apart from the core (whose calls reach a connection through its sink).
struct Shared {
    limits: RelayLimits,
    log: Log,
    now: Clock,
    key: SigningKey,
    key_raw: [u8; 32],
    port: Cell<u16>,
    closing: Cell<bool>,
    /// Told when the last connection has gone (`close` waits for it, as Node's `server.close` does).
    all_gone: Notify,
    by_token: RefCell<HashMap<[u8; TOKEN_BYTES], Rc<ConnCell>>>,
    accept: Option<Accept>,
    guest: Option<Guest>,
    /// The core and the connections, for the timers that need them.
    state: RefCell<std::rc::Weak<RefCell<State>>>,
    /// Hashes the channel-1 packets taken both ways (keyed per run).
    hasher: RandomState,
    /// The datagram being sent, sealed (one buffer for every send: the hot path allocates nothing).
    datagram: RefCell<Vec<u8>>,
}

/// The core and the connections.
struct State {
    core: Core,
    conns: IndexMap<u64, Rc<ConnCell>>,
    per_address: IndexMap<String, u32>,
    next_cid: u64,
}

/// A running relay.
pub struct Relay {
    /// The port it listens on, TCP and UDP.
    pub port: u16,
    /// The relay's own key id.
    pub id: String,
    shared: Rc<Shared>,
    state: Rc<RefCell<State>>,
    tasks: Vec<JoinHandle<()>>,
    udp: Vec<Rc<Udp>>,
    /// What the registry link last heard (empty with no link).
    registry: Rc<Kept>,
}

impl ConnCell {
    fn tag(&self) -> String {
        let c = self.c.borrow();
        if c.id.is_empty() { c.address.clone() } else { format!("{} {}", c.address, c.id) }
    }

    fn done(&self) -> bool {
        self.c.borrow().stage == Stage::Closed
    }

    /// The session the connection leaves the core with, and the token freed (`leaveCore` but the core's leave, which
    /// the caller makes).
    fn leave_core(&self, sh: &Shared) -> Option<Session> {
        for t in [&self.hello, &self.watch] {
            if let Some(t) = t.borrow_mut().take() {
                t.abort();
            }
        }
        let mut c = self.c.borrow_mut();
        if let Some(t) = c.token {
            sh.by_token.borrow_mut().remove(&t);
        }
        // (its UDP address is of no use any more, and would hold the relay's socket)
        c.udp = None;
        c.session.take()
    }

    /// `socket.destroy()`: the writer stopped where it is, the reader told to stop (it ends the connection).
    fn destroy(&self) {
        self.c.borrow_mut().close = Close::Destroy;
        if let Some(t) = self.writer.borrow_mut().take() {
            t.abort();
        }
        self.kill.notify_one();
    }

    /// `refuse`: told why, then closed. `why` is the relay's own text, never a client's. The session to take out of the
    /// core (none when it has gone already).
    fn refuse(self: &Rc<Self>, sh: &Shared, why: &str) -> Option<Session> {
        if self.done() {
            return None;
        }
        say_log(&sh.log, &format!("{} refused: {why}", self.tag()));
        let s = self.leave_core(sh);
        {
            let mut c = self.c.borrow_mut();
            c.stage = Stage::Closed;
            let m = serde_json::to_vec(&ServerMessage::Refused { why: why.to_string() }).expect("a refusal serialises");
            let _ = put_frame(&mut c, FT_JSON, &[&m]);
            c.close = Close::End;
        }
        self.wake.notify_one();
        let me = self.clone();
        let linger = spawn(&sh.log, async move {
            tokio::time::sleep(Duration::from_millis(LINGER_MS)).await;
            me.destroy();
        });
        *self.linger.borrow_mut() = Some(linger);
        s
    }

    /// `lost`: closed with nothing more said (it cannot be told: its buffer is full).
    fn lost(&self, sh: &Shared, why: &str) -> Option<Session> {
        if self.done() {
            return None;
        }
        say_log(&sh.log, &format!("{} dropped: {why}", self.tag()));
        let s = self.leave_core(sh);
        self.c.borrow_mut().stage = Stage::Closed;
        self.destroy();
        s
    }

    /// `write`: a frame of type `ty` whose body is `parts` (sealed from the challenge on: [`put_frame`]). False when
    /// the client reads too slowly and the connection was lost (its session the core's to let go: returned in `lost`),
    /// or when the frame could not be made (too long, or the sealing's counter spent: lost too).
    fn write(&self, sh: &Shared, ty: u8, parts: &[&[u8]], lost: &mut Option<Session>) -> bool {
        let why = {
            let mut c = self.c.borrow_mut();
            if c.stage == Stage::Closed {
                return true;
            }
            if put_frame(&mut c, ty, parts).is_err() {
                "a frame too long, or its sealing spent"
            } else if ((c.out.len() + c.flight) as f64) <= sh.limits.send_buffer_bytes {
                drop(c);
                self.wake.notify_one();
                return true;
            } else {
                "reads too slowly"
            }
        };
        *lost = self.lost(sh, why);
        false
    }

    /// `say`: a message to the client; one too long for a frame loses the connection (logged).
    fn say(&self, sh: &Shared, m: &ServerMessage, lost: &mut Option<Session>) -> bool {
        let body = serde_json::to_vec(m).expect("a control message serialises");
        if body.len() + 1 > MAX_FRAME {
            let kind =
                serde_json::to_value(m).ok().and_then(|v| v["t"].as_str().map(str::to_string)).unwrap_or_default();
            *lost = self.lost(sh, &format!("a {kind} message too long for a frame"));
            return false;
        }
        self.write(sh, FT_JSON, &[&body], lost)
    }

    /// A channel-1 packet taken by TCP (`way` 0) or UDP (1): true when it came the other way already (the client sent
    /// it both ways), so it is dropped; it is passed on, and counted against the match bytes, once.
    fn both_ways(&self, sh: &Shared, way: usize, handle: u32, bytes: &[u8]) -> bool {
        let now = (sh.now)();
        let h = sh.hasher.hash_one((handle, bytes));
        let mut c = self.c.borrow_mut();
        for w in &mut c.both_ways {
            while w.front().is_some_and(|&(_, at)| now - at > BOTH_WAYS_MS) {
                w.pop_front();
            }
        }
        let other = &mut c.both_ways[1 - way];
        if let Some(k) = other.iter().position(|&(x, _)| x == h) {
            other.remove(k);
            return true;
        }
        let mine = &mut c.both_ways[way];
        if mine.len() >= BOTH_WAYS_KEPT {
            mine.pop_front();
        }
        mine.push_back((h, now));
        false
    }

    /// The link to `id` is over: the handles naming it either way are freed.
    fn free_peer(&self, id: &str) {
        let mut c = self.c.borrow_mut();
        if let Some(h) = c.in_by_id.remove(id) {
            c.in_handles.remove(&h);
        }
        c.out_handles.remove(id);
    }
}

/// How the core reaches the player of a connection (`core.join`'s CorePlayer).
struct Sink {
    conn: Rc<ConnCell>,
    shared: Rc<Shared>,
}

impl CorePlayer for Sink {
    fn send(&mut self, m: &ServerMessage) -> Taken {
        // a closed link's handles are freed (a later packet either way gets a new one)
        if let ServerMessage::PeerClosed { id } = m {
            self.conn.free_peer(id);
        }
        // (a direct host's guest: a lobby's change that leaves it out, it left, was kicked, or the lobby closed)
        if self.shared.guest.is_some()
            && let ServerMessage::Lobby { lobby, members, closed } = m
        {
            let mut c = self.conn.c.borrow_mut();
            let out = closed.is_some() || !members.as_ref().is_some_and(|m| m.contains(&c.id));
            if out && c.lobbies.shift_remove(lobby) {
                drop(c);
                guest_watch(&self.shared, &self.conn);
            }
        }
        let mut lost = None;
        if self.conn.say(&self.shared, m, &mut lost) { Taken::Yes } else { Taken::Lost }
    }

    /// A packet from `from`: its handle told first; channel 1 by UDP while the client's probes say it hears UDP.
    fn packet(&mut self, channel: u8, from: &str, bytes: &[u8]) -> Taken {
        let sh = &*self.shared;
        let (handle, fresh) = {
            let mut c = self.conn.c.borrow_mut();
            if c.stage != Stage::In {
                return Taken::Yes;
            }
            match c.out_handles.get(from) {
                Some(&h) => (h, false),
                None => {
                    if c.out_handles.len() >= MAX_PEER_HANDLES {
                        // no handle left for one more peer: the core closes that link and tells both sides
                        return Taken::NoHandle;
                    }
                    let h = c.next_handle;
                    c.next_handle += 1;
                    c.out_handles.insert(from.to_string(), h);
                    (h, true)
                }
            }
        };
        let mut lost = None;
        if fresh && !self.conn.say(sh, &ServerMessage::Peer { handle, id: from.to_string() }, &mut lost) {
            return Taken::Lost;
        }
        {
            let mut c = self.conn.c.borrow_mut();
            let c = &mut *c;
            // (a new handle's first packet goes on TCP behind its peer message, so it is not dropped as unknown)
            if channel == 1
                && !fresh
                && !sh.closing.get()
                && let (Some(u), Some(token), Some(tx)) = (c.udp.as_ref(), c.token, c.tx.as_mut())
                && u.heard
                && (sh.now)() - u.at < UDP_FRESH_MS
            {
                // (a datagram the socket cannot take now is lost, as a match packet may be; one the counter cannot seal
                // any more is not sent)
                let mut d = sh.datagram.borrow_mut();
                tx.datagram_into(&mut d, &token, UDP_MATCH, &[&handle.to_be_bytes(), bytes]);
                if !d.is_empty() {
                    let _ = u.sock.send.send_to(&d, u.addr);
                }
                // Deviation: the port's own rule. A client whose last probe is late (its UDP way may be dying) is sent
                // channel 1 on TCP too, until a probe comes again or UDP is given up (UDP_FRESH_MS).
                if (sh.now)() - u.at <= UDP_PROBE_MS + UDP_LATE_MS {
                    return Taken::Yes;
                }
            }
        }
        let ty = if channel == 0 { FT_DATA } else { FT_MATCH };
        if self.conn.write(sh, ty, &[&handle.to_be_bytes(), bytes], &mut lost) { Taken::Yes } else { Taken::Lost }
    }

    fn refuse(&mut self, why: &str) {
        self.conn.c.borrow_mut().session = None;
        self.conn.refuse(&self.shared, why);
    }
}

/// Runs `f`; a panic in it closes this connection (and is logged by its kind), never the program.
fn guard(sh: &Shared, st: &RefCell<State>, conn: &Rc<ConnCell>, f: impl FnOnce()) {
    if catch_unwind(AssertUnwindSafe(f)).is_err() {
        say_log(&sh.log, &format!("{} internal error: a panic", conn.tag()));
        let s = conn.lost(sh, "internal error");
        if let (Some(s), Ok(mut st)) = (s, st.try_borrow_mut()) {
            let now = (sh.now)();
            let _ = catch_unwind(AssertUnwindSafe(|| st.core.leave(&s, now)));
        }
    }
}

/// A direct host's guest in no lobby is dropped after the join's time (the guest rules' watch): the timer is
/// started anew at the welcome and at each change that leaves the guest in none.
fn guest_watch(sh: &Rc<Shared>, conn: &Rc<ConnCell>) {
    let Some(g) = &sh.guest else { return };
    if let Some(t) = conn.watch.borrow_mut().take() {
        t.abort();
    }
    if conn.done() || !conn.c.borrow().lobbies.is_empty() {
        return;
    }
    let (sh2, conn2, ms) = (sh.clone(), conn.clone(), g.join_within_ms);
    let t = tokio::task::spawn_local(async move {
        tokio::time::sleep(Duration::from_secs_f64(ms / 1000.0)).await;
        if conn2.done() || !conn2.c.borrow().lobbies.is_empty() {
            return;
        }
        let Some(st) = sh2.state.borrow().upgrade() else { return };
        guard(&sh2, &st, &conn2, || {
            let s = conn2.refuse(&sh2, "in no lobby");
            leave(&mut st.borrow_mut(), &sh2, s);
        });
    });
    *conn.watch.borrow_mut() = Some(t);
}

/// The core's leave of a session the connection gave up, if any.
fn leave(st: &mut State, sh: &Shared, s: Option<Session>) {
    if let Some(s) = s {
        st.core.leave(&s, (sh.now)());
    }
}

/// The core's park of a session whose connection was lost without a bye (closed, silent, a reader too slow), if any:
/// its seat is kept for a resume.
fn park(st: &mut State, sh: &Shared, s: Option<Session>) {
    if let Some(s) = s {
        st.core.park(&s, (sh.now)());
    }
}

fn on_data(sh: &Rc<Shared>, st: &mut State, conn: &Rc<ConnCell>, chunk: &[u8]) {
    {
        let mut c = conn.c.borrow_mut();
        if c.stage == Stage::Closed {
            return;
        }
        c.heard = (sh.now)();
        c.reader.feed(chunk);
    }
    // (one frame at a time: the prove switches the reader to the sealed one, which reads the rest of the chunk)
    loop {
        let f = conn.c.borrow_mut().reader.next();
        let Some(f) = f else { break };
        on_frame(sh, st, conn, f.ty, &f.body);
        if conn.done() {
            return;
        }
    }
    let (bad, (pending, over)) = {
        let c = conn.c.borrow();
        (c.reader.bad(), c.reader.pending())
    };
    if let Some(why) = bad {
        let s = conn.refuse(sh, why);
        leave(st, sh, s);
    } else if pending as f64 > sh.limits.frame_bytes + over as f64 {
        let s = conn.refuse(sh, "frame too long");
        leave(st, sh, s);
    }
}

fn on_frame(sh: &Rc<Shared>, st: &mut State, conn: &Rc<ConnCell>, ty: u8, body: &[u8]) {
    let refuse = |st: &mut State, why: &str| {
        let s = conn.refuse(sh, why);
        leave(st, sh, s);
    };
    if (body.len() + 1) as f64 > sh.limits.frame_bytes {
        return refuse(st, "frame too long");
    }
    if ty == FT_JSON {
        let now = (sh.now)();
        if !conn.c.borrow_mut().control.take(1.0, now) {
            return refuse(st, "too many messages");
        }
        let Some(m) = read_json(&js_json(body)) else { return refuse(st, "bad message") };
        return on_message(sh, st, conn, m);
    }
    if ty != FT_DATA && ty != FT_MATCH {
        return refuse(st, "bad frame");
    }
    if conn.c.borrow().stage != Stage::In {
        return refuse(st, "bad message");
    }
    let Some(p) = read_packet(body) else { return refuse(st, "bad frame") };
    let (to, session) = {
        let c = conn.c.borrow();
        (c.in_handles.get(&p.handle).cloned(), c.session.clone())
    };
    // (every channel-0 data frame counts for a resume, whatever its handle)
    if let (FT_DATA, Some(s)) = (ty, &session) {
        st.core.took_data(s);
    }
    if ty == FT_MATCH && conn.both_ways(sh, 0, p.handle, p.bytes) {
        return;
    }
    if let (Some(to), Some(s)) = (to, session) {
        st.core.packet(&s, if ty == FT_DATA { 0 } else { 1 }, &to, p.bytes, (sh.now)());
    }
}

fn on_message(sh: &Rc<Shared>, st: &mut State, conn: &Rc<ConnCell>, m: Map<String, Value>) {
    let refuse = |st: &mut State, why: &str| {
        let s = conn.refuse(sh, why);
        leave(st, sh, s);
    };
    let t = m.get("t").and_then(Value::as_str).unwrap_or("");
    let stage = conn.c.borrow().stage;
    if stage == Stage::Hello {
        if t != "hello" {
            return refuse(st, "bad message");
        }
        if m.get("v").and_then(Value::as_f64) != Some(f64::from(RELAY_WIRE_VERSION)) {
            return refuse(st, &format!("wire version not {RELAY_WIRE_VERSION}"));
        }
        let raw = unb64::<32>(m.get("key"));
        let nonce = unb64::<NONCE_BYTES>(m.get("nonce"));
        let client_kx = unb64::<KX_BYTES>(m.get("kx"));
        let app_ok = match m.get("app") {
            None => true,
            Some(Value::String(s)) => js_len(s) <= 128,
            Some(_) => false,
        };
        let got = match m.get("got") {
            None | Some(Value::Null) => Some(None),
            Some(v) => v.as_u64().filter(|&g| g as f64 <= 9007199254740991.0).map(Some),
        };
        let (Some(raw), Some(nonce), Some(client_kx), true, Some(got)) = (raw, nonce, client_kx, app_ok, got) else {
            return refuse(st, "bad hello");
        };
        if bad_public_key(&raw) {
            return refuse(st, "bad key");
        }
        let Ok(client_key) = VerifyingKey::from_bytes(&raw) else { return refuse(st, "bad key") };
        let kx = KxSecret::fresh();
        let relay_kx = kx.public();
        // (a kx of small order: the exchange's secret would be all zero)
        let Some(secret) = shared(kx, &client_kx) else { return refuse(st, "bad key") };
        let mut relay_nonce = [0u8; NONCE_BYTES];
        rand::fill(&mut relay_nonce);
        let t = Transcript {
            client_key: raw,
            relay_key: sh.key_raw,
            client_nonce: nonce,
            relay_nonce,
            client_kx,
            relay_kx,
        };
        let sig = sh.key.sign(&handshake_bytes(Side::Relay, &t));
        let (tx, opener, datagrams) = split(&derive(&secret, &t), Side::Relay);
        {
            let mut c = conn.c.borrow_mut();
            c.id = key_id(&raw);
            c.client_key = Some(client_key);
            c.transcript = Some(t);
            c.stage = Stage::Prove;
            c.got = got;
        }
        let challenge = ServerMessage::Challenge {
            v: RELAY_WIRE_VERSION,
            nonce: b64(&relay_nonce),
            key: b64(&sh.key_raw),
            kx: b64(&relay_kx),
            sig: b64(&sig.to_bytes()),
        };
        let mut lost = None;
        // (the challenge is the last plain frame the relay sends)
        if conn.say(sh, &challenge, &mut lost) {
            let mut c = conn.c.borrow_mut();
            c.tx = Some(tx);
            c.opener = Some(opener);
            c.datagrams = Some(datagrams);
        }
        return;
    }
    if stage == Stage::Prove {
        if t != "prove" {
            return refuse(st, "bad message");
        }
        let sig = unb64::<64>(m.get("sig"));
        let ok = {
            let c = conn.c.borrow();
            let (Some(k), Some(tr)) = (c.client_key.as_ref(), c.transcript.as_ref()) else {
                unreachable!("a prove stage")
            };
            sig.is_some_and(|s| k.verify(&handshake_bytes(Side::Client, tr), &Signature::from_bytes(&s)).is_ok())
        };
        if !ok {
            return refuse(st, "bad signature");
        }
        let (id, address) = {
            let c = conn.c.borrow();
            (c.id.clone(), c.address.clone())
        };
        if sh.guest.as_ref().is_some_and(|g| g.host == id) {
            return refuse(st, "that is the host's own id");
        }
        let sink = Sink { conn: conn.clone(), shared: sh.clone() };
        let joined = st.core.join(&id, &address, Box::new(sink), (sh.now)());
        let s = match joined {
            Ok((s, _took_over)) => s,
            Err(why) => return refuse(st, &why),
        };
        let got = conn.c.borrow().got;
        let resumed = st.core.resume(&s, got, (sh.now)());
        let token = {
            let by = sh.by_token.borrow();
            let mut token = [0u8; TOKEN_BYTES];
            loop {
                rand::fill(&mut token);
                if !by.contains_key(&token) {
                    break token;
                }
            }
        };
        {
            let mut c = conn.c.borrow_mut();
            c.session = Some(s);
            c.stage = Stage::In;
            c.token = Some(token);
            // (what the client sends after its prove is sealed: the bytes already fed after it are read so)
            let opener = c.opener.take().expect("a prove stage has its opener");
            if let Reader::Plain(r) = &mut c.reader {
                let rest = r.take_rest();
                c.reader = Reader::Sealed(SealedReader::new(opener, rest));
            }
        }
        sh.by_token.borrow_mut().insert(token, conn.clone());
        say_log(&sh.log, &format!("{address} {id} in"));
        let mut lost = None;
        let s = conn.c.borrow().session.clone().expect("a session");
        // (the game protocol of the cores this relay hosts, the one mvs-host's core names in its `server`)
        let proto = Some(mvs_protocol::version::PROTOCOL);
        let welcome = ServerMessage::Welcome { id, token: b64(&token), udp: sh.port.get(), resumed, proto };
        if !conn.say(sh, &welcome, &mut lost) {
            return park(st, sh, lost);
        }
        // (what the seat is owed goes after the welcome)
        st.core.resumed(&s, (sh.now)());
        // (a player in no lobby has join_within_ms to join one)
        guest_watch(sh, conn);
        return;
    }
    match t {
        "req" => {
            let id = m.get("id").and_then(Value::as_f64).filter(|f| f.fract() == 0.0 && f.abs() <= 9007199254740991.0);
            let (Some(id), true) = (id, m.get("op").is_some_and(Value::is_string)) else {
                return refuse(st, "bad message");
            };
            let Some(s) = conn.c.borrow().session.clone() else { return };
            let op = m.get("op").and_then(Value::as_str).unwrap_or("").to_owned();
            let lobby = m.get("lobby").and_then(Value::as_str).map(str::to_owned);
            let guest = sh.guest.is_some();
            let result = if guest && !GUEST_OPS.contains(&op.as_str()) {
                Err(crate::core::BAD)
            } else {
                st.core.request(&s, &Value::Object(m), (sh.now)())
            };
            if guest && result.is_ok() {
                if let (true, Some(l)) = (op == "join", &lobby) {
                    conn.c.borrow_mut().lobbies.insert(l.clone());
                } else if let (true, Some(l)) = (op == "leave", &lobby)
                    && conn.c.borrow_mut().lobbies.shift_remove(l)
                {
                    guest_watch(sh, conn);
                }
            }
            let answer = match result {
                Ok(value) => ServerMessage::Res { id: id as i64, ok: true, value: Some(value), error: None },
                // (the core's reasons are its own words: EOS's result names)
                Err(e) => ServerMessage::Res { id: id as i64, ok: false, value: None, error: Some(e.to_string()) },
            };
            if conn.c.borrow().session.is_some() {
                let mut lost = None;
                conn.say(sh, &answer, &mut lost);
                park(st, sh, lost);
            }
        }
        "peer" => {
            let handle = m
                .get("handle")
                .and_then(Value::as_f64)
                .filter(|h| h.fract() == 0.0 && (1.0..=f64::from(u32::MAX)).contains(h));
            let id = m.get("id").and_then(Value::as_str).filter(|id| js_len(id) <= 128);
            let (Some(handle), Some(id)) = (handle, id) else { return refuse(st, "bad message") };
            let handle = handle as u32;
            let mut c = conn.c.borrow_mut();
            if handle <= c.last_in {
                drop(c);
                return refuse(st, "a peer handle used twice");
            }
            c.last_in = handle;
            if let Some(old) = c.in_by_id.get(id).copied() {
                c.in_handles.remove(&old);
            } else if c.in_handles.len() >= MAX_PEER_HANDLES {
                drop(c);
                return refuse(st, "too many peers");
            }
            c.in_handles.insert(handle, id.to_string());
            c.in_by_id.insert(id.to_string(), handle);
        }
        "closePeer" => {
            let Some(id) = m.get("id").and_then(Value::as_str) else { return refuse(st, "bad message") };
            conn.free_peer(id);
            let s = conn.c.borrow().session.clone();
            if let Some(s) = s {
                st.core.close_peer(&s, id, (sh.now)());
            }
        }
        "ping" => {
            let mut lost = None;
            conn.say(sh, &ServerMessage::Pong, &mut lost);
            park(st, sh, lost);
        }
        "pong" => {}
        // (a leave on purpose: no seat is kept for it)
        "bye" => {
            say_log(&sh.log, &format!("{} left", conn.tag()));
            let s = conn.leave_core(sh);
            conn.c.borrow_mut().stage = Stage::Closed;
            conn.destroy();
            leave(st, sh, s);
        }
        _ => refuse(st, "bad message"),
    }
}

/// A sealed datagram whose token is this connection's (`raw`: opened in place).
fn on_datagram(sh: &Rc<Shared>, st: &mut State, conn: &Rc<ConnCell>, sock: &Rc<Udp>, raw: &mut [u8], from: SocketAddr) {
    // (a datagram from another IP than this connection's is not its client's: a sniffed token, or a spoofed source;
    // one that does not open, or came before, is not its client's either)
    let body = {
        let mut c = conn.c.borrow_mut();
        if c.stage != Stage::In || plain(&from.ip()) != c.address {
            return;
        }
        let Some(o) = c.datagrams.as_mut() else { return };
        o.open(raw)
    };
    let Some(d) = body.and_then(read_udp_body) else { return };
    if d.kind == UDP_PROBE {
        if sh.closing.get() {
            return;
        }
        let mut c = conn.c.borrow_mut();
        let c = &mut *c;
        c.udp = Some(UdpPeer { sock: sock.clone(), addr: from, at: (sh.now)(), heard: d.heard });
        if let (Some(token), Some(tx)) = (c.token, c.tx.as_mut()) {
            let mut out = sh.datagram.borrow_mut();
            tx.datagram_into(&mut out, &token, UDP_PROBE_ACK, &[]);
            if !out.is_empty() {
                let _ = sock.send.send_to(&out, from);
            }
        }
        return;
    }
    if d.kind != UDP_MATCH || conn.both_ways(sh, 1, d.handle, d.bytes) {
        return;
    }
    let (to, s) = {
        let c = conn.c.borrow();
        (c.in_handles.get(&d.handle).cloned(), c.session.clone())
    };
    if let (Some(to), Some(s)) = (to, s) {
        st.core.packet(&s, 1, &to, d.bytes, (sh.now)());
    }
}

/// The TCP connection's end (`closed`): out of the counts, its player out of the core.
fn on_closed(sh: &Rc<Shared>, st: &mut State, conn: &Rc<ConnCell>) {
    if !conn.done() {
        say_log(&sh.log, &format!("{} closed", conn.tag()));
    }
    conn.c.borrow_mut().stage = Stage::Closed;
    for t in [&conn.hello, &conn.linger] {
        if let Some(t) = t.borrow_mut().take() {
            t.abort();
        }
    }
    if st.conns.shift_remove(&conn.cid).is_none() {
        return;
    }
    if st.conns.is_empty() {
        sh.all_gone.notify_waiters();
    }
    let group = conn.c.borrow().group.clone();
    let n = st.per_address.get(&group).copied().unwrap_or(1) - 1;
    if n > 0 {
        st.per_address.insert(group, n);
    } else {
        st.per_address.shift_remove(&group);
    }
    let s = conn.leave_core(sh);
    park(st, sh, s);
}

/// Waits for the first of a read and the connection's kill: `None` when killed.
async fn read_or_kill(r: &mut OwnedReadHalf, buf: &mut [u8], kill: &Notify) -> Option<io::Result<usize>> {
    let mut read = pin!(r.read(buf));
    let mut killed = pin!(kill.notified());
    std::future::poll_fn(|cx| {
        if killed.as_mut().poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        read.as_mut().poll(cx).map(Some)
    })
    .await
}

async fn reader(sh: Rc<Shared>, st: Rc<RefCell<State>>, conn: Rc<ConnCell>, mut r: OwnedReadHalf) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match read_or_kill(&mut r, &mut buf, &conn.kill).await {
            Some(Ok(n)) if n > 0 => {
                let chunk = &buf[..n];
                guard(&sh, &st, &conn, || on_data(&sh, &mut st.borrow_mut(), &conn, chunk));
            }
            _ => break,
        }
    }
    conn.destroy();
    guard(&sh, &st, &conn, || on_closed(&sh, &mut st.borrow_mut(), &conn));
}

async fn writer(conn: Rc<ConnCell>, mut w: OwnedWriteHalf) {
    loop {
        let (buf, close) = {
            let mut c = conn.c.borrow_mut();
            let buf = std::mem::take(&mut c.out);
            c.flight = buf.len();
            (buf, c.close)
        };
        if close == Close::Destroy {
            return;
        }
        if !buf.is_empty() {
            let mut at = 0;
            while at < buf.len() {
                match w.write(&buf[at..]).await {
                    Ok(n) if n > 0 => {
                        at += n;
                        conn.c.borrow_mut().flight = buf.len() - at;
                    }
                    _ => {
                        conn.destroy();
                        return;
                    }
                }
            }
            continue;
        }
        if close == Close::End {
            let _ = w.shutdown().await;
            // (the reader runs on until the other side closes or the linger destroys it)
            return;
        }
        conn.wake.notified().await;
    }
}

fn on_accept(sh: &Rc<Shared>, st: &Rc<RefCell<State>>, socket: TcpStream, peer: SocketAddr) {
    if sh.accept.as_ref().is_some_and(|a| !a(&peer.ip())) {
        return;
    }
    let _ = socket.set_nodelay(true);
    let address = plain(&peer.ip());
    let group = address_group(&address);
    let mut s = st.borrow_mut();
    let n = s.per_address.get(&group).copied().unwrap_or(0);
    let refused = if sh.closing.get() {
        Some("relay stopping")
    } else if f64::from(n) >= sh.limits.connections_per_address {
        Some("too many connections from this address")
    } else if s.conns.len() as f64 >= 2.0 * sh.limits.players {
        Some("relay full")
    } else {
        None
    };
    if let Some(why) = refused {
        say_log(&sh.log, &format!("{address} refused: {why}"));
        drop(s);
        spawn(&sh.log, async move {
            let (mut r, mut w) = socket.into_split();
            let _ = tokio::time::timeout(Duration::from_millis(LINGER_MS), async {
                if let Ok(f) = json_frame(&ServerMessage::Refused { why: why.to_string() }) {
                    let _ = w.write_all(&f).await;
                }
                let _ = w.shutdown().await;
                let mut buf = [0u8; 1024];
                while matches!(r.read(&mut buf).await, Ok(n) if n > 0) {}
            })
            .await;
        });
        return;
    }
    s.per_address.insert(group.clone(), n + 1);
    let cid = s.next_cid;
    s.next_cid += 1;
    let now = (sh.now)();
    let conn = Rc::new(ConnCell {
        cid,
        c: RefCell::new(Conn {
            address,
            group,
            reader: Reader::Plain(FrameReader::new()),
            stage: Stage::Hello,
            heard: now,
            control: TokenBucket::per_second(sh.limits.control_per_second, now, 1.0),
            client_key: None,
            transcript: None,
            tx: None,
            opener: None,
            datagrams: None,
            id: String::new(),
            session: None,
            token: None,
            in_handles: HashMap::new(),
            in_by_id: HashMap::new(),
            last_in: 0,
            out_handles: HashMap::new(),
            next_handle: 1,
            udp: None,
            out: Vec::new(),
            flight: 0,
            close: Close::Open,
            lobbies: indexmap::IndexSet::new(),
            got: None,
            both_ways: [VecDeque::new(), VecDeque::new()],
        }),
        wake: Notify::new(),
        kill: Notify::new(),
        writer: RefCell::new(None),
        hello: RefCell::new(None),
        linger: RefCell::new(None),
        watch: RefCell::new(None),
    });
    s.conns.insert(cid, conn.clone());
    drop(s);
    let (r, w) = socket.into_split();
    spawn(&sh.log, reader(sh.clone(), st.clone(), conn.clone(), r));
    *conn.writer.borrow_mut() = Some(spawn(&sh.log, writer(conn.clone(), w)));
    // the hello and the prove within helloMs of the start
    let (sh2, st2, c2) = (sh.clone(), st.clone(), conn.clone());
    let hello = spawn(&sh.log, async move {
        tokio::time::sleep(Duration::from_secs_f64(sh2.limits.hello_ms / 1000.0)).await;
        if matches!(c2.c.borrow().stage, Stage::Hello | Stage::Prove) {
            guard(&sh2, &st2, &c2, || {
                let s = c2.refuse(&sh2, "no hello in time");
                leave(&mut st2.borrow_mut(), &sh2, s);
            });
        }
    });
    *conn.hello.borrow_mut() = Some(hello);
}

fn tcp_listener(addr: SocketAddr, dual: bool) -> io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if dual {
        s.set_only_v6(false)?;
    }
    #[cfg(unix)]
    s.set_reuse_address(true)?;
    s.set_nonblocking(true)?;
    s.bind(&addr.into())?;
    s.listen(511)?;
    TcpListener::from_std(s.into())
}

fn udp_socket(addr: SocketAddr, v6_only: bool) -> io::Result<Udp> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        s.set_only_v6(v6_only)?;
    }
    s.set_nonblocking(true)?;
    s.bind(&addr.into())?;
    let send = s.try_clone()?.into();
    Ok(Udp { recv: UdpSocket::from_std(s.into())?, send })
}

/// TCP first (port 0 picks one), then UDP on the same number; a port 0 whose UDP twin is taken tries another.
fn bind(host: &str, port: u16, log: &Log) -> io::Result<(Vec<TcpListener>, Vec<Rc<Udp>>, u16)> {
    let dual = host.is_empty() || host == "::";
    let mut tries = 0;
    loop {
        let tcp = if dual {
            match tcp_listener(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port), true) {
                Ok(l) => l,
                // a PC with no IPv6 listens on IPv4 alone
                Err(_) => tcp_listener(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port), false)?,
            }
        } else {
            let ip: IpAddr =
                host.parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "not an IP address"))?;
            tcp_listener(SocketAddr::new(ip, port), false)?
        };
        let p = tcp.local_addr()?.port();
        let udp: io::Result<Vec<Rc<Udp>>> = (|| {
            if dual {
                let mut v = vec![Rc::new(udp_socket(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), p), false)?)];
                match udp_socket(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), p), true) {
                    Ok(s) => v.push(Rc::new(s)),
                    Err(e) => say_log(log, &format!("udp6 not bound: {e}")),
                }
                Ok(v)
            } else {
                let ip: IpAddr =
                    host.parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "not an IP address"))?;
                Ok(vec![Rc::new(udp_socket(SocketAddr::new(ip, p), true)?)])
            }
        })();
        match udp {
            Ok(u) => return Ok((vec![tcp], u, p)),
            Err(e) => {
                drop(tcp);
                tries += 1;
                if port != 0 || tries > 5 {
                    return Err(e);
                }
            }
        }
    }
}

/// `startRelay`: a relay listening on its port. Called inside a `LocalSet` of a current-thread runtime.
pub fn start_relay(o: Options) -> io::Result<Relay> {
    let limits = relay_limits(&o.limits);
    let log: Log = Rc::new(RefCell::new(o.log.unwrap_or_else(|| Box::new(|_| {}))));
    let now: Clock = o.now.unwrap_or_else(|| {
        let t0 = Instant::now();
        Rc::new(move || t0.elapsed().as_secs_f64() * 1000.0)
    });
    let core_log = log.clone();
    let mut core = Core::new(&limits, o.hosted, Box::new(move |l| say_log(&core_log, l)));
    // (a direct host's guests keep no seat: their links are LAN ones)
    if o.guest.is_some() {
        core.keep_no_seats();
    }
    if !o.shorts {
        core.give_no_shorts();
    }
    let key = load_key(o.key_file.as_deref())?;
    let key_raw = key.verifying_key().to_bytes();
    let id = key_id(&key_raw);
    let (listeners, udp, port) = bind(&o.host, o.port, &log)?;
    let shared = Rc::new(Shared {
        limits,
        log,
        now,
        key,
        key_raw,
        port: Cell::new(port),
        closing: Cell::new(false),
        all_gone: Notify::new(),
        by_token: RefCell::new(HashMap::new()),
        accept: o.accept,
        guest: o.guest,
        state: RefCell::new(std::rc::Weak::new()),
        hasher: RandomState::new(),
        datagram: RefCell::new(Vec::with_capacity(MAX_SEALED_DATAGRAM)),
    });
    let state =
        Rc::new(RefCell::new(State { core, conns: IndexMap::new(), per_address: IndexMap::new(), next_cid: 1 }));
    *shared.state.borrow_mut() = Rc::downgrade(&state);
    let mut tasks = Vec::new();
    for l in listeners {
        let (sh, st) = (shared.clone(), state.clone());
        tasks.push(spawn(&shared.log, async move {
            loop {
                match l.accept().await {
                    Ok((socket, peer)) => {
                        if catch_unwind(AssertUnwindSafe(|| on_accept(&sh, &st, socket, peer))).is_err() {
                            say_log(&sh.log, "connection not taken: internal error: a panic");
                        }
                    }
                    // (an error on the listening socket once it listens, as too many open files at an accept: logged,
                    // it goes on)
                    Err(e) => {
                        say_log(&sh.log, &format!("tcp error: {e}"));
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }
        }));
    }
    for sock in &udp {
        let (sh, st, sock) = (shared.clone(), state.clone(), sock.clone());
        tasks.push(spawn(&shared.log, async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let (n, from) = match sock.recv.recv_from(&mut buf).await {
                    Ok(x) => x,
                    // (Windows reports an ICMP port unreachable of an earlier send as an error here)
                    Err(_) => continue,
                };
                if sh.accept.as_ref().is_some_and(|a| !a(&from.ip())) {
                    continue;
                }
                let Some(token) = datagram_token(&buf[..n]) else { continue };
                let Some(conn) = sh.by_token.borrow().get(&token).cloned() else { continue };
                let raw = &mut buf[..n];
                guard(&sh, &st, &conn, || on_datagram(&sh, &mut st.borrow_mut(), &conn, &sock, raw, from));
            }
        }));
    }
    {
        let (sh, st) = (shared.clone(), state.clone());
        tasks.push(spawn(&shared.log, async move {
            let mut t = tokio::time::interval(Duration::from_millis(SWEEP_MS));
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                t.tick().await;
                let now = (sh.now)();
                let conns: Vec<Rc<ConnCell>> = st.borrow().conns.values().cloned().collect();
                for c in conns {
                    if now - c.c.borrow().heard > sh.limits.silent_ms {
                        guard(&sh, &st, &c, || {
                            let s = c.refuse(&sh, "silent");
                            park(&mut st.borrow_mut(), &sh, s);
                        });
                    }
                }
                // (the seats parked for RESUME_MS leave; a panic in it is logged, never the program's end)
                if catch_unwind(AssertUnwindSafe(|| st.borrow_mut().core.expire(now))).is_err() {
                    say_log(&sh.log, "seats not let go: internal error: a panic");
                }
            }
        }));
    }
    {
        let (sh, st) = (shared.clone(), state.clone());
        tasks.push(spawn(&shared.log, async move {
            let mut t = tokio::time::interval(Duration::from_secs_f64(REFEREE_PUMP_MS / 1000.0));
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                t.tick().await;
                // (a referee's or a host core's own panic is caught and logged in the core)
                let mut s = st.borrow_mut();
                s.core.pump((sh.now)());
            }
        }));
    }
    let registry = Rc::new(Kept::default());
    if let Some(r) = o.registry {
        let st = state.clone();
        let link = Link {
            o: r,
            key: shared.key.clone(),
            log: shared.log.clone(),
            counts: Box::new(move || counts_of(&st.borrow().core)),
            kept: registry.clone(),
        };
        tasks.push(spawn(&shared.log, registry_link::run(link)));
    }
    Ok(Relay { port, id, shared, state, tasks, udp, registry })
}

impl Relay {
    /// Runs `f` on the relay's core with its clock (tests, a direct host's own player in process).
    pub fn with_core<R>(&self, f: impl FnOnce(&mut Core, f64) -> R) -> R {
        let now = (self.shared.now)();
        f(&mut self.state.borrow_mut().core, now)
    }

    /// The relays the registry last told of, by id (empty: none, or no link).
    pub fn registry_relays(&self) -> Vec<RelayEntry> {
        self.registry.relays.borrow().values().cloned().collect()
    }

    /// Whether the registry link is checked in now.
    pub fn registry_up(&self) -> bool {
        self.registry.up.get()
    }

    /// `close`: every connection told 'relay stopping', the sockets closed (the registry link's too).
    pub async fn close(mut self) {
        if self.shared.closing.replace(true) {
            return;
        }
        // the listening sockets and the UDP loops go first: their ports are free once close returns
        for t in &self.tasks {
            t.abort();
        }
        for t in self.tasks.drain(..) {
            let _ = t.await;
        }
        let gone = self.shared.all_gone.notified();
        let mut gone = pin!(gone);
        gone.as_mut().enable();
        let conns: Vec<Rc<ConnCell>> = self.state.borrow().conns.values().cloned().collect();
        for c in &conns {
            guard(&self.shared, &self.state, c, || {
                let s = c.refuse(&self.shared, "relay stopping");
                leave(&mut self.state.borrow_mut(), &self.shared, s);
            });
        }
        self.udp.clear();
        // every connection ends: its client closes it, or the linger does
        if !self.state.borrow().conns.is_empty() {
            gone.await;
        }
    }
}
