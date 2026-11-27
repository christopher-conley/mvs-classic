//! The registry on a port: the TCP connections of `mvs_protocol::registry_wire`, each started link a member of a
//! [`Registry`], and the name lookups and address checks the registry asks for. Everything runs on one thread (a
//! current-thread runtime and a `LocalSet`): [`start_registry`] is called inside a `LocalSet`.

use std::cell::{Cell, OnceCell, RefCell};
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::pin::{Pin, pin};
use std::rc::{Rc, Weak};
use std::task::Poll;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use indexmap::IndexMap;
use mvs_protocol::registry_wire::{
    FromRegistry, REGISTRY_WIRE_VERSION, START_MS, ToRegistry, registry_handshake_bytes,
};
use mvs_protocol::relay_seal::{FrameOpener, KX_BYTES, KxSecret, SealedReader, TxSeal, derive, shared, split};
use mvs_protocol::relay_wire::{
    ClientMessage, FT_JSON, FrameReader, FrameTooLong, MAX_FRAME, NONCE_BYTES, RELAY_WIRE_VERSION, Side, Transcript,
    bad_public_key, handshake_bytes, json_frame, key_id, read_json,
};
use mvs_relay::server::load_key;
use serde_json::{Map, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::core::{Admission, Due, Limits, Member, MemberKey, Mode, Proof, Registry};
use crate::rules::{Bans, NO_IPV6};

/// A refused connection is closed this long after its refused { why }, if the other side has not closed it (ms), as
/// the relay's.
const LINGER_MS: u64 = 2000;
/// The bytes a connection may hold for a relay that reads too slowly; past them it is dropped. Deviation: the port's
/// own bound, the relay's default send buffer.
const SEND_BUFFER_BYTES: usize = 1 << 20;

/// A link not started (hello to welcome) within `Options::start_ms`.
pub const NOT_STARTED: &str = "the start took too long";
/// What every member is told at `Running::close`.
pub const STOPPING: &str = "registry stopping";

/// One log line's taker (`Options::log`).
pub type LogLine = Box<dyn FnMut(&str)>;
type Log = Rc<RefCell<LogLine>>;

/// `Options::resolve`: a host name and port looked up: its first IPv4 address, or why there is none.
pub type Resolve = Rc<dyn Fn(String, u16) -> Pin<Box<dyn Future<Output = Lookup>>>>;
/// `Options::prove`: the id of the key a relay at that address proved within the time (ms); None for none.
pub type Prove = Rc<dyn Fn(SocketAddrV4, f64) -> Pin<Box<dyn Future<Output = Option<String>>>>>;

/// What a registry is started with.
pub struct Options {
    /// 0 picks one.
    pub port: u16,
    /// An IPv4 address; "" is 0.0.0.0. The registry listens on IPv4 only.
    pub host: String,
    /// The registry's key (its id); made for this run only when None.
    pub key_file: Option<PathBuf>,
    pub admission: Admission,
    pub limits: Limits,
    pub log: Option<LogLine>,
    /// How often `expire` runs, a start's time, and the address check's time (ms): 1000, START_MS, 5000. A name
    /// lookup is given the address check's time too.
    pub sweep_ms: f64,
    pub start_ms: f64,
    pub prove_ms: f64,
    /// The name lookup (None: tokio's `lookup_host`, its first IPv4 answer; an error is `Lookup::Failed`) and the
    /// address check (None:
    /// [`prove_key`]). Tests pass their own.
    pub resolve: Option<Resolve>,
    pub prove: Option<Prove>,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            port: 0,
            host: String::new(),
            key_file: None,
            admission: Admission { mode: Mode::Open, approved: Vec::new(), bans: Bans::new(Vec::new()) },
            limits: Limits::default(),
            log: None,
            sweep_ms: 1000.0,
            start_ms: START_MS,
            prove_ms: 5000.0,
            resolve: None,
            prove: None,
        }
    }
}

/// `v` ms as a Duration: 0 for a negative or NaN one, a long time for one past range.
fn duration(v: f64) -> Duration {
    Duration::from_secs_f64(if v > 0.0 { v.min(1e12) / 1000.0 } else { 0.0 })
}

fn say_log(log: &Log, line: &str) {
    (log.borrow_mut())(line);
}

fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

/// Standard base64 of exactly `N` bytes, else None.
fn unb64<const N: usize>(v: Option<&Value>) -> Option<[u8; N]> {
    let s = v?.as_str()?;
    if s.len() > 4 * N.div_ceil(3) {
        return None;
    }
    STANDARD.decode(s).ok()?.try_into().ok()
}

/// Runs a task of the registry: a panic in it that no guard caught ends the program with code 1, logged (for a
/// service manager to start it again); a registry that went on would be half broken.
fn spawn(log: &Log, f: impl Future<Output = ()> + 'static) -> JoinHandle<()> {
    tokio::task::spawn_local(Fatal { log: log.clone(), f: Box::pin(f) })
}

struct Fatal<F> {
    log: Log,
    f: Pin<Box<F>>,
}

impl<F: Future<Output = ()>> Future for Fatal<F> {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<()> {
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

/// A connection's reader of the relay's frames: plain until its prove is taken, sealed from the next frame on.
enum Reader {
    Plain(FrameReader),
    Sealed(SealedReader),
}

impl Reader {
    #[allow(clippy::should_implement_trait, reason = "a reader fed between calls, not an iterator")]
    fn next(&mut self) -> Option<mvs_protocol::relay_wire::Frame> {
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

    /// Why the stream cannot be read on, if it cannot.
    fn bad(&self) -> Option<&'static str> {
        match self {
            Reader::Plain(r) => r.bad.then_some("frame too long"),
            Reader::Sealed(r) => r.bad.then_some("bad seal"),
        }
    }
}

/// One TCP connection: its start, then its member.
struct Conn {
    source: Ipv4Addr,
    reader: Reader,
    stage: Stage,
    /// The id of its hello's key (empty before it).
    id: String,
    relay_key: Option<VerifyingKey>,
    transcript: Option<Transcript>,
    /// What the registry sends with, from the challenge on: every frame after the challenge is sealed.
    tx: Option<TxSeal>,
    /// What the relay's frames are opened with once its prove is taken (the reader's from then on).
    opener: Option<FrameOpener>,
    /// Bytes not yet handed to the writer.
    out: Vec<u8>,
    /// Bytes the writer holds, not yet taken by the socket.
    flight: usize,
    close: Close,
}

/// A connection: its state, its member key, and the wakers of its writer and reader.
struct ConnCell {
    key: OnceCell<MemberKey>,
    c: RefCell<Conn>,
    /// The writer has bytes or a close to see.
    wake: Notify,
    /// The reader stops (the connection is destroyed).
    kill: Notify,
    writer: RefCell<Option<JoinHandle<()>>>,
    /// Its start's timer (cleared at the welcome) and its refusal's linger.
    start: RefCell<Option<JoinHandle<()>>>,
    linger: RefCell<Option<JoinHandle<()>>>,
}

/// What every connection and task shares, apart from the core and the connections.
struct Shared {
    log: Log,
    t0: Instant,
    key: SigningKey,
    key_raw: [u8; 32],
    start_ms: f64,
    prove_ms: f64,
    resolve: Option<Resolve>,
    prove: Option<Prove>,
    closing: Cell<bool>,
    /// Told when the last connection has gone (`close` waits for it).
    all_gone: Notify,
    /// The core and the connections, for the tasks that need them.
    state: RefCell<Weak<RefCell<State>>>,
}

impl Shared {
    /// The registry's clock: ms since its start, monotonic.
    fn now(&self) -> f64 {
        self.t0.elapsed().as_secs_f64() * 1000.0
    }

    fn state(&self) -> Option<Rc<RefCell<State>>> {
        self.state.borrow().upgrade()
    }
}

struct State {
    core: Registry,
    conns: IndexMap<MemberKey, Rc<ConnCell>>,
}

/// A running registry.
pub struct Running {
    /// The port it listens on.
    pub port: u16,
    /// The registry's own key id.
    pub id: String,
    shared: Rc<Shared>,
    state: Rc<RefCell<State>>,
    tasks: Vec<JoinHandle<()>>,
}

/// Appends one frame of type `ty` whose body is `body` to the connection's bytes out: sealed once the challenge is
/// sent, plain before.
fn put_frame(c: &mut Conn, ty: u8, body: &[u8]) -> Result<(), FrameTooLong> {
    if let Some(tx) = c.tx.as_mut() {
        return tx.frame_into(&mut c.out, ty, &[body]);
    }
    if body.len() + 1 > MAX_FRAME {
        return Err(FrameTooLong);
    }
    c.out.extend_from_slice(&u32::try_from(body.len() + 1).map_err(|_| FrameTooLong)?.to_be_bytes());
    c.out.push(ty);
    c.out.extend_from_slice(body);
    Ok(())
}

impl ConnCell {
    fn member_key(&self) -> Option<MemberKey> {
        self.key.get().copied()
    }

    /// Who it is in a log line: its key's id, or before its hello its source address.
    fn who(&self) -> String {
        let c = self.c.borrow();
        if c.id.is_empty() { c.source.to_string() } else { c.id.clone() }
    }

    fn done(&self) -> bool {
        self.c.borrow().stage == Stage::Closed
    }

    fn stop_timers(&self) {
        for t in [&self.start, &self.linger] {
            if let Some(t) = t.borrow_mut().take() {
                t.abort();
            }
        }
    }

    /// The writer stopped where it is, the reader told to stop (it ends the connection).
    fn destroy(&self) {
        self.c.borrow_mut().close = Close::Destroy;
        if let Some(t) = self.writer.borrow_mut().take() {
            t.abort();
        }
        self.kill.notify_one();
    }

    /// Told why, then closed. `why` is the registry's own text, never a relay's. Logs nothing: the caller does, or the
    /// core did.
    fn refuse(self: &Rc<Self>, sh: &Shared, why: &str) {
        if self.done() {
            return;
        }
        self.stop_timers();
        {
            let mut c = self.c.borrow_mut();
            c.stage = Stage::Closed;
            let m = serde_json::to_vec(&FromRegistry::Refused { why: why.to_string() }).expect("a refusal serializes");
            let _ = put_frame(&mut c, FT_JSON, &m);
            c.close = Close::End;
        }
        self.wake.notify_one();
        let me = self.clone();
        let linger = spawn(&sh.log, async move {
            tokio::time::sleep(Duration::from_millis(LINGER_MS)).await;
            me.destroy();
        });
        *self.linger.borrow_mut() = Some(linger);
    }

    /// Closed with nothing more said (it cannot be told: its buffer is full), logged.
    fn lost(&self, sh: &Shared, why: &str) {
        if self.done() {
            return;
        }
        say_log(&sh.log, &format!("dropped {}: {why}", self.who()));
        self.stop_timers();
        self.c.borrow_mut().stage = Stage::Closed;
        self.destroy();
    }

    /// A message to the relay (sealed from the challenge on). False when the relay reads too slowly, or the frame
    /// could not be made: the connection is lost.
    fn say(&self, sh: &Shared, m: &FromRegistry) -> bool {
        let body = serde_json::to_vec(m).expect("a message serializes");
        let why = {
            let mut c = self.c.borrow_mut();
            if c.stage == Stage::Closed {
                return true;
            }
            if put_frame(&mut c, FT_JSON, &body).is_err() {
                "a frame too long, or its sealing spent"
            } else if c.out.len() + c.flight <= SEND_BUFFER_BYTES {
                drop(c);
                self.wake.notify_one();
                return true;
            } else {
                "reads too slowly"
            }
        };
        self.lost(sh, why);
        false
    }
}

/// How the core reaches one connection: its calls touch that connection's own cell alone.
struct Sink {
    conn: Rc<ConnCell>,
    shared: Rc<Shared>,
}

impl Member for Sink {
    fn send(&mut self, m: &FromRegistry) -> bool {
        self.conn.say(&self.shared, m)
    }

    fn refuse(&mut self, why: &str) {
        self.conn.refuse(&self.shared, why);
    }
}

/// The registry's own refusal of a connection (not one of the core's rules): logged, told, closed, and let go by the
/// core.
fn refuse(sh: &Shared, st: &mut State, conn: &Rc<ConnCell>, why: &str) {
    if conn.done() {
        return;
    }
    say_log(&sh.log, &format!("refused {}: {why}", conn.who()));
    conn.refuse(sh, why);
    if let Some(k) = conn.member_key() {
        st.core.leave(k, sh.now());
    }
}

/// Runs `f`; a panic in it closes this connection (logged), never the program.
fn guard(sh: &Shared, st: &RefCell<State>, conn: &Rc<ConnCell>, f: impl FnOnce()) {
    if catch_unwind(AssertUnwindSafe(f)).is_err() {
        panicked(sh, st, conn);
    }
}

/// A panic while `conn`'s bytes or its check were handled: the connection closed, the core told it left.
fn panicked(sh: &Shared, st: &RefCell<State>, conn: &Rc<ConnCell>) {
    conn.lost(sh, "internal error: a panic");
    if let (Some(k), Ok(mut s)) = (conn.member_key(), st.try_borrow_mut()) {
        let now = sh.now();
        let _ = catch_unwind(AssertUnwindSafe(|| s.core.leave(k, now)));
    }
}

/// Runs `f` on the state for member `k`'s check; a panic in it closes that member's connection, never the program.
/// None: it panicked.
fn with_member<R>(sh: &Shared, st: &RefCell<State>, k: MemberKey, f: impl FnOnce(&mut State, f64) -> R) -> Option<R> {
    let now = sh.now();
    match catch_unwind(AssertUnwindSafe(|| f(&mut st.borrow_mut(), now))) {
        Ok(r) => Some(r),
        Err(_) => {
            let conn = st.try_borrow().ok().and_then(|s| s.conns.get(&k).cloned());
            match conn {
                Some(c) => panicked(sh, st, &c),
                None => say_log(&sh.log, "a check: internal error: a panic"),
            }
            None
        }
    }
}

fn on_data(sh: &Rc<Shared>, st: &mut State, conn: &Rc<ConnCell>, chunk: &[u8]) {
    {
        let mut c = conn.c.borrow_mut();
        if c.stage == Stage::Closed {
            return;
        }
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
    let bad = conn.c.borrow().reader.bad();
    if let Some(why) = bad {
        refuse(sh, st, conn, why);
    }
}

fn on_frame(sh: &Rc<Shared>, st: &mut State, conn: &Rc<ConnCell>, ty: u8, body: &[u8]) {
    if ty != FT_JSON {
        return refuse(sh, st, conn, "bad frame");
    }
    let Some(m) = read_json(body) else { return refuse(sh, st, conn, "bad message") };
    let stage = conn.c.borrow().stage;
    match stage {
        Stage::Hello => on_hello(sh, st, conn, &m),
        Stage::Prove => on_prove(sh, st, conn, &m),
        Stage::In => on_message(sh, st, conn, m),
        Stage::Closed => {}
    }
}

/// The hello: its version and key, the core's word on its id, then the challenge (the last plain frame sent).
fn on_hello(sh: &Rc<Shared>, st: &mut State, conn: &Rc<ConnCell>, m: &Map<String, Value>) {
    let Some(k) = conn.member_key() else { return };
    if m.get("t").and_then(Value::as_str) != Some("hello") {
        return refuse(sh, st, conn, "bad message");
    }
    if m.get("v").and_then(Value::as_f64) != Some(f64::from(REGISTRY_WIRE_VERSION)) {
        return refuse(sh, st, conn, &format!("wire version not {REGISTRY_WIRE_VERSION}"));
    }
    let raw = unb64::<32>(m.get("key"));
    let nonce = unb64::<NONCE_BYTES>(m.get("nonce"));
    let relay_kx = unb64::<KX_BYTES>(m.get("kx"));
    let (Some(raw), Some(nonce), Some(relay_kx)) = (raw, nonce, relay_kx) else {
        return refuse(sh, st, conn, "bad hello");
    };
    if bad_public_key(&raw) {
        return refuse(sh, st, conn, "bad key");
    }
    let Ok(relay_key) = VerifyingKey::from_bytes(&raw) else { return refuse(sh, st, conn, "bad key") };
    let kx = KxSecret::fresh();
    let registry_kx = kx.public();
    // (a kx of small order: the exchange's secret would be all zero)
    let Some(secret) = shared(kx, &relay_kx) else { return refuse(sh, st, conn, "bad key") };
    let id = key_id(&raw);
    conn.c.borrow_mut().id = id.clone();
    // (the core refuses a banned id, or one off the list, before any signature is made)
    if st.core.hello(k, &id, sh.now()).is_err() {
        return;
    }
    let mut registry_nonce = [0u8; NONCE_BYTES];
    rand::fill(&mut registry_nonce);
    let t = Transcript {
        client_key: raw,
        relay_key: sh.key_raw,
        client_nonce: nonce,
        relay_nonce: registry_nonce,
        client_kx: relay_kx,
        relay_kx: registry_kx,
    };
    let sig = sh.key.sign(&registry_handshake_bytes(Side::Relay, &t));
    let (tx, opener, _) = split(&derive(&secret, &t), Side::Relay);
    {
        let mut c = conn.c.borrow_mut();
        c.relay_key = Some(relay_key);
        c.transcript = Some(t);
        c.stage = Stage::Prove;
    }
    let challenge = FromRegistry::Challenge {
        v: REGISTRY_WIRE_VERSION,
        key: b64(&sh.key_raw),
        nonce: b64(&registry_nonce),
        kx: b64(&registry_kx),
        sig: b64(&sig.to_bytes()),
    };
    if conn.say(sh, &challenge) {
        let mut c = conn.c.borrow_mut();
        c.tx = Some(tx);
        c.opener = Some(opener);
    } else {
        st.core.leave(k, sh.now());
    }
}

/// The prove: the relay's signature over the link's own context, then the welcome (sealed, as all after it).
fn on_prove(sh: &Rc<Shared>, st: &mut State, conn: &Rc<ConnCell>, m: &Map<String, Value>) {
    let Some(k) = conn.member_key() else { return };
    if m.get("t").and_then(Value::as_str) != Some("prove") {
        return refuse(sh, st, conn, "bad message");
    }
    let sig = unb64::<64>(m.get("sig"));
    let ok = {
        let c = conn.c.borrow();
        let (Some(key), Some(t)) = (c.relay_key.as_ref(), c.transcript.as_ref()) else { return };
        sig.is_some_and(|s| key.verify(&registry_handshake_bytes(Side::Client, t), &Signature::from_bytes(&s)).is_ok())
    };
    if !ok {
        return refuse(sh, st, conn, "bad signature");
    }
    {
        let mut c = conn.c.borrow_mut();
        // (what the relay sends after its prove is sealed: the bytes already fed after it are read so)
        let Some(opener) = c.opener.take() else { return };
        if let Reader::Plain(r) = &mut c.reader {
            let rest = r.take_rest();
            c.reader = Reader::Sealed(SealedReader::new(opener, rest));
        }
    }
    st.core.proved(k, sh.now());
    if conn.done() {
        return;
    }
    conn.c.borrow_mut().stage = Stage::In;
    if let Some(t) = conn.start.borrow_mut().take() {
        t.abort();
    }
    let id = conn.c.borrow().id.clone();
    if !conn.say(sh, &FromRegistry::Welcome { id }) {
        st.core.leave(k, sh.now());
    }
}

/// A started member's message: its check-in (the lookup and check begun) or a beat.
fn on_message(sh: &Rc<Shared>, st: &mut State, conn: &Rc<ConnCell>, m: Map<String, Value>) {
    let Some(k) = conn.member_key() else { return };
    let now = sh.now();
    match serde_json::from_value::<ToRegistry>(Value::Object(m)) {
        Ok(ToRegistry::CheckIn { address, wire, proto, counts }) => {
            if let Ok((host, port)) = st.core.check_in(k, &address, wire, proto, counts, now) {
                spawn(&sh.log, check(sh.clone(), k, host, port));
            }
        }
        Ok(ToRegistry::Beat { counts }) => st.core.beat(k, counts, now),
        _ => refuse(sh, st, conn, "bad message"),
    }
}

/// A name lookup's outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// Its first IPv4 address: checked there.
    Ip(Ipv4Addr),
    /// It answered, with no IPv4 address: a check-in's is refused NO_IPV6.
    NoIpv4,
    /// No answer (an error, or none within the address check's time): checked again later.
    Failed,
}

/// `host` looked up (an IPv4 literal is its own answer) within the address check's time.
async fn lookup(sh: &Shared, host: &str, port: u16) -> Lookup {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Lookup::Ip(ip);
    }
    let answer = async {
        match &sh.resolve {
            Some(r) => r(host.to_string(), port).await,
            None => match tokio::net::lookup_host((host, port)).await {
                Ok(addrs) => addrs
                    .filter_map(|a| match a {
                        SocketAddr::V4(a) => Some(*a.ip()),
                        SocketAddr::V6(_) => None,
                    })
                    .next()
                    .map_or(Lookup::NoIpv4, Lookup::Ip),
                Err(_) => Lookup::Failed,
            },
        }
    };
    tokio::time::timeout(duration(sh.prove_ms), answer).await.unwrap_or(Lookup::Failed)
}

/// The address check of member `k` at `at`: Proved when the key proved there is its own, OtherKey for another,
/// NoAnswer for none within the time. None: the member is gone.
async fn proof(sh: &Shared, k: MemberKey, at: SocketAddrV4) -> Option<Proof> {
    let id = sh.state()?.borrow().conns.get(&k)?.c.borrow().id.clone();
    let dial = match &sh.prove {
        Some(p) => p(at, sh.prove_ms),
        None => Box::pin(prove_key(at, sh.prove_ms)),
    };
    Some(match tokio::time::timeout(duration(sh.prove_ms), dial).await {
        Ok(Some(proved)) if proved == id => Proof::Proved,
        Ok(Some(_)) => Proof::OtherKey,
        _ => Proof::NoAnswer,
    })
}

/// A check of member `k` (its check-in's, or one due again): the lookup, the core's word on the address, the address
/// check, and its outcome back to the core.
async fn check(sh: Rc<Shared>, k: MemberKey, host: String, port: u16) {
    let found = lookup(&sh, &host, port).await;
    let Some(st) = sh.state() else { return };
    let resolved = match found {
        Lookup::Ip(ip) => with_member(&sh, &st, k, |s, now| s.core.resolved(k, ip, now)),
        Lookup::NoIpv4 => {
            with_member(&sh, &st, k, |s, _| {
                if let Some(conn) = s.conns.get(&k).cloned() {
                    refuse(&sh, s, &conn, NO_IPV6);
                }
            });
            return;
        }
        Lookup::Failed => {
            with_member(&sh, &st, k, |s, now| s.core.unresolved(k, now));
            return;
        }
    };
    let Some(Ok(at)) = resolved else { return };
    drop(st);
    let Some(p) = proof(&sh, k, at).await else { return };
    let Some(st) = sh.state() else { return };
    with_member(&sh, &st, k, |s, now| s.core.verified(k, p, now));
}

/// A listed member's refresh: its host name looked up again; a new address is checked and, proved, listed. A lookup
/// with no answer, or no IPv4 one, keeps the listed address until the next refresh.
async fn refresh(sh: Rc<Shared>, k: MemberKey, host: String, port: u16) {
    let found = lookup(&sh, &host, port).await;
    let Some(st) = sh.state() else { return };
    let Lookup::Ip(ip) = found else {
        with_member(&sh, &st, k, |s, now| s.core.unresolved(k, now));
        return;
    };
    let Some(Some(to)) = with_member(&sh, &st, k, |s, now| s.core.refreshed(k, ip, now)) else { return };
    drop(st);
    let Some(p) = proof(&sh, k, to).await else { return };
    let Some(st) = sh.state() else { return };
    with_member(&sh, &st, k, |s, now| s.core.moved(k, to, p, now));
}

fn on_closed(sh: &Shared, st: &mut State, conn: &Rc<ConnCell>) {
    conn.stop_timers();
    conn.c.borrow_mut().stage = Stage::Closed;
    let Some(k) = conn.member_key() else { return };
    if st.conns.shift_remove(&k).is_none() {
        return;
    }
    st.core.leave(k, sh.now());
    if st.conns.is_empty() {
        sh.all_gone.notify_waiters();
    }
}

/// Waits for the first of a read and the connection's kill: None when killed.
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

/// A connection the core refused at its connect: told why as a plain frame and closed, no start.
fn refuse_plain(sh: &Shared, socket: TcpStream, why: &'static str) {
    spawn(&sh.log, async move {
        let (mut r, mut w) = socket.into_split();
        let _ = tokio::time::timeout(Duration::from_millis(LINGER_MS), async {
            if let Ok(f) = json_frame(&FromRegistry::Refused { why: why.to_string() }) {
                let _ = w.write_all(&f).await;
            }
            let _ = w.shutdown().await;
            let mut buf = [0u8; 1024];
            while matches!(r.read(&mut buf).await, Ok(n) if n > 0) {}
        })
        .await;
    });
}

fn on_accept(sh: &Rc<Shared>, st: &Rc<RefCell<State>>, socket: TcpStream, peer: SocketAddr) {
    // (the listener is IPv4 only)
    let SocketAddr::V4(peer) = peer else { return };
    if sh.closing.get() {
        return refuse_plain(sh, socket, STOPPING);
    }
    let _ = socket.set_nodelay(true);
    let conn = Rc::new(ConnCell {
        key: OnceCell::new(),
        c: RefCell::new(Conn {
            source: *peer.ip(),
            reader: Reader::Plain(FrameReader::new()),
            stage: Stage::Hello,
            id: String::new(),
            relay_key: None,
            transcript: None,
            tx: None,
            opener: None,
            out: Vec::new(),
            flight: 0,
            close: Close::Open,
        }),
        wake: Notify::new(),
        kill: Notify::new(),
        writer: RefCell::new(None),
        start: RefCell::new(None),
        linger: RefCell::new(None),
    });
    let sink = Sink { conn: conn.clone(), shared: sh.clone() };
    let mut s = st.borrow_mut();
    let k = match s.core.connect(*peer.ip(), Box::new(sink), sh.now()) {
        Ok(k) => k,
        // (the core logged it)
        Err(why) => return refuse_plain(sh, socket, why),
    };
    let _ = conn.key.set(k);
    s.conns.insert(k, conn.clone());
    drop(s);
    let (r, w) = socket.into_split();
    spawn(&sh.log, reader(sh.clone(), st.clone(), conn.clone(), r));
    *conn.writer.borrow_mut() = Some(spawn(&sh.log, writer(conn.clone(), w)));
    // (the hello and the prove within start_ms of the connection)
    let (sh2, st2, c2) = (sh.clone(), st.clone(), conn.clone());
    let start = spawn(&sh.log, async move {
        tokio::time::sleep(duration(sh2.start_ms)).await;
        if matches!(c2.c.borrow().stage, Stage::Hello | Stage::Prove) {
            guard(&sh2, &st2, &c2, || refuse(&sh2, &mut st2.borrow_mut(), &c2, NOT_STARTED));
        }
    });
    *conn.start.borrow_mut() = Some(start);
}

/// Every `sweep_ms`: the core's `expire`, then each check and refresh due, as a task of its own.
async fn sweep(sh: Rc<Shared>, st: Rc<RefCell<State>>, every: f64) {
    let mut t = tokio::time::interval(duration(every).max(Duration::from_millis(1)));
    t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        t.tick().await;
        let now = sh.now();
        let due = catch_unwind(AssertUnwindSafe(|| {
            let mut s = st.borrow_mut();
            s.core.expire(now);
            s.core.due(now)
        }));
        let Ok(due) = due else {
            say_log(&sh.log, "the sweep: internal error: a panic");
            continue;
        };
        for d in due {
            match d {
                Due::Check { key, host, port } => spawn(&sh.log, check(sh.clone(), key, host, port)),
                Due::Refresh { key, host, port } => spawn(&sh.log, refresh(sh.clone(), key, host, port)),
            };
        }
    }
}

/// A registry listening on its port. Called inside a `LocalSet` of a current-thread runtime.
pub fn start_registry(o: Options) -> io::Result<Running> {
    let ip: Ipv4Addr = if o.host.is_empty() {
        Ipv4Addr::UNSPECIFIED
    } else {
        o.host.parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "not an IPv4 address"))?
    };
    let log: Log = Rc::new(RefCell::new(o.log.unwrap_or_else(|| Box::new(|_| {}))));
    let key = load_key(o.key_file.as_deref())?;
    let key_raw = key.verifying_key().to_bytes();
    let id = key_id(&key_raw);
    let listener = std::net::TcpListener::bind(SocketAddrV4::new(ip, o.port))?;
    listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(listener)?;
    let port = listener.local_addr()?.port();
    let core_log = log.clone();
    let core = Registry::new(RELAY_WIRE_VERSION, o.admission, o.limits, Box::new(move |l| say_log(&core_log, l)));
    let shared = Rc::new(Shared {
        log,
        t0: Instant::now(),
        key,
        key_raw,
        start_ms: o.start_ms,
        prove_ms: o.prove_ms,
        resolve: o.resolve,
        prove: o.prove,
        closing: Cell::new(false),
        all_gone: Notify::new(),
        state: RefCell::new(Weak::new()),
    });
    let state = Rc::new(RefCell::new(State { core, conns: IndexMap::new() }));
    *shared.state.borrow_mut() = Rc::downgrade(&state);
    let mut tasks = Vec::new();
    {
        let (sh, st) = (shared.clone(), state.clone());
        tasks.push(spawn(&shared.log, async move {
            loop {
                match listener.accept().await {
                    Ok((socket, peer)) => {
                        if catch_unwind(AssertUnwindSafe(|| on_accept(&sh, &st, socket, peer))).is_err() {
                            say_log(&sh.log, "connection not taken: internal error: a panic");
                        }
                    }
                    // (an error on the listening socket once it listens, as too many open files: logged, it goes on)
                    Err(e) => {
                        say_log(&sh.log, &format!("tcp error: {e}"));
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }
        }));
    }
    tasks.push(spawn(&shared.log, sweep(shared.clone(), state.clone(), o.sweep_ms)));
    Ok(Running { port, id, shared, state, tasks })
}

impl Running {
    /// Runs `f` on the registry's core with its clock (tests, the web pages).
    pub fn with_core<R>(&self, f: impl FnOnce(&mut Registry, f64) -> R) -> R {
        let now = self.shared.now();
        f(&mut self.state.borrow_mut().core, now)
    }

    /// Every member told STOPPING, the socket closed; returns once every connection has ended.
    pub async fn close(mut self) {
        if self.shared.closing.replace(true) {
            return;
        }
        // (the listening socket goes first: its port is free once close returns)
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
            guard(&self.shared, &self.state, c, || refuse(&self.shared, &mut self.state.borrow_mut(), c, STOPPING));
        }
        // every connection ends: its relay closes it, or the linger does
        if !self.state.borrow().conns.is_empty() {
            gone.await;
        }
    }
}

/// Dials a relay at `at` as a game would, reads its challenge, checks the signature, and gives the id of the key it
/// proved; sends no prove. None on any failure or after `ms`. It speaks this build's relay wire.
pub async fn prove_key(at: SocketAddrV4, ms: f64) -> Option<String> {
    tokio::time::timeout(duration(ms), challenge_at(at)).await.ok().flatten()
}

async fn challenge_at(at: SocketAddrV4) -> Option<String> {
    let mut s = TcpStream::connect(at).await.ok()?;
    let _ = s.set_nodelay(true);
    // (a key of this dial's own: the relay learns nothing of the registry)
    let mut secret = [0u8; 32];
    rand::fill(&mut secret);
    let raw = SigningKey::from_bytes(&secret).verifying_key().to_bytes();
    let mut nonce = [0u8; NONCE_BYTES];
    rand::fill(&mut nonce);
    let kx = KxSecret::fresh().public();
    let hello = ClientMessage::Hello {
        v: RELAY_WIRE_VERSION,
        key: b64(&raw),
        nonce: b64(&nonce),
        kx: b64(&kx),
        app: None,
        got: None,
    };
    s.write_all(&json_frame(&hello).ok()?).await.ok()?;
    let mut fr = FrameReader::new();
    let mut buf = vec![0u8; 4096];
    let f = loop {
        if let Some(f) = fr.next() {
            break f;
        }
        let n = s.read(&mut buf).await.ok()?;
        if n == 0 || fr.bad {
            return None;
        }
        fr.feed(&buf[..n]);
    };
    if f.ty != FT_JSON {
        return None;
    }
    let m = read_json(&f.body)?;
    if m.get("t")?.as_str()? != "challenge" {
        return None;
    }
    let relay_raw = unb64::<32>(m.get("key"))?;
    let t = Transcript {
        client_key: raw,
        relay_key: relay_raw,
        client_nonce: nonce,
        relay_nonce: unb64::<NONCE_BYTES>(m.get("nonce"))?,
        client_kx: kx,
        relay_kx: unb64::<KX_BYTES>(m.get("kx"))?,
    };
    let sig = Signature::from_bytes(&unb64::<64>(m.get("sig"))?);
    if bad_public_key(&relay_raw) {
        return None;
    }
    VerifyingKey::from_bytes(&relay_raw).ok()?.verify(&handshake_bytes(Side::Relay, &t), &sig).ok()?;
    Some(key_id(&relay_raw))
}
