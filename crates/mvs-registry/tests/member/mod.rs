//! A relay's side of the registry link, written for the wire checks: dial, hello, read the challenge, prove, then
//! send what a check says. Its reader derives the link's keys at the challenge and opens what follows it; what it
//! sends is sealed from its prove on.
#![allow(dead_code)]

use std::cell::RefCell;
use std::future::Future;
use std::pin::pin;
use std::rc::Rc;
use std::task::Poll;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use mvs_protocol::registry_wire::{REGISTRY_WIRE_VERSION, registry_handshake_bytes};
use mvs_protocol::relay_seal::{FrameOpener, KxSecret, SealedReader, TxSeal, derive, shared, split};
use mvs_protocol::relay_wire::{
    FT_JSON, Frame, FrameReader, NONCE_BYTES, RELAY_WIRE_VERSION, Side, Transcript, json_frame, key_id, read_json,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;

/// The game protocol the checks' relays check in with.
pub const PROTO: u32 = 33;

/// Runs a check on a current-thread runtime and a `LocalSet`, as the registry runs.
pub fn run(f: impl Future<Output = ()>) {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    tokio::task::LocalSet::new().block_on(&rt, f);
}

pub async fn sleep(ms: u64) {
    tokio::time::sleep(Duration::from_millis(ms)).await;
}

pub async fn until(what: &str, ms: u64, mut cond: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_millis(ms);
    while !cond() {
        assert!(Instant::now() < end, "condition not met: {what}");
        sleep(5).await;
    }
}

pub fn new_key() -> SigningKey {
    let mut s = [0u8; 32];
    rand::fill(&mut s);
    SigningKey::from_bytes(&s)
}

pub fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

pub fn unb64(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().expect("base64 text")).expect("base64")
}

#[derive(Default)]
pub struct Inner {
    /// The messages not yet taken by a wait.
    pub got: Vec<Value>,
    /// The `t` of every message the registry sent, in order.
    pub seen: Vec<String>,
    pub closed: bool,
    /// The last hello's nonce and X25519 secret, until the challenge takes them.
    pub hello: Option<([u8; NONCE_BYTES], KxSecret)>,
    /// What this side sends with, once a challenge gave the keys.
    pub tx: Option<TxSeal>,
    /// Its frames are sealed (its prove was sent).
    pub sealing: bool,
    /// A sealed frame from the registry did not open.
    pub bad_seal: bool,
}

enum Reader {
    Plain(FrameReader),
    Sealed(SealedReader),
}

/// One relay's link to the registry.
pub struct Member {
    pub key: SigningKey,
    pub raw: [u8; 32],
    pub id: String,
    pub inner: Rc<RefCell<Inner>>,
    pub wake: Rc<Notify>,
    out: RefCell<Option<mpsc::UnboundedSender<Vec<u8>>>>,
    /// The last hello's X25519 public key.
    kx_public: RefCell<[u8; 32]>,
    tasks: RefCell<Vec<JoinHandle<()>>>,
}

impl Drop for Member {
    fn drop(&mut self) {
        for t in self.tasks.borrow_mut().drain(..) {
            t.abort();
        }
    }
}

/// The keys of a challenge for the hello that asked for it, put in `i`: the opener of the frames after it.
fn keys_of(i: &mut Inner, raw: [u8; 32], kx_public: [u8; 32], f: &Frame) -> Option<FrameOpener> {
    let m = read_json(&f.body)?;
    if m.get("t")?.as_str()? != "challenge" {
        return None;
    }
    let (nonce, kx) = i.hello.take()?;
    let field = |k: &str| -> Option<[u8; 32]> { STANDARD.decode(m.get(k)?.as_str()?).ok()?.try_into().ok() };
    let t = Transcript {
        client_key: raw,
        relay_key: field("key")?,
        client_nonce: nonce,
        relay_nonce: field("nonce")?,
        client_kx: kx_public,
        relay_kx: field("kx")?,
    };
    let secret = shared(kx, &t.relay_kx)?;
    let (tx, opener, _) = split(&derive(&secret, &t), Side::Client);
    i.tx = Some(tx);
    Some(opener)
}

/// The first of two futures to finish (true: the first).
async fn first<A: Future, B: Future>(a: A, b: B) -> bool {
    let (mut a, mut b) = (pin!(a), pin!(b));
    std::future::poll_fn(|cx| {
        if a.as_mut().poll(cx).is_ready() {
            return Poll::Ready(true);
        }
        b.as_mut().poll(cx).map(|_| false)
    })
    .await
}

impl Member {
    /// A connection to the registry on `127.0.0.1:port`, nothing sent.
    pub async fn dial(port: u16, key: Option<SigningKey>) -> Rc<Member> {
        let key = key.unwrap_or_else(new_key);
        let raw = key.verifying_key().to_bytes();
        let sock = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (mut r, mut w) = sock.into_split();
        let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let m = Rc::new(Member {
            id: key_id(&raw),
            key,
            raw,
            inner: Rc::default(),
            wake: Rc::default(),
            out: RefCell::new(Some(tx)),
            kx_public: RefCell::new([0; 32]),
            tasks: RefCell::new(Vec::new()),
        });
        // (the other side's end ends this side too)
        let ended = Rc::new(Notify::new());
        let (inner, wake, ended2) = (m.inner.clone(), m.wake.clone(), ended.clone());
        let me = Rc::downgrade(&m);
        let reader = tokio::task::spawn_local(async move {
            let mut fr = Reader::Plain(FrameReader::new());
            let mut buf = vec![0u8; 64 * 1024];
            while let Ok(n) = r.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                let mut i = inner.borrow_mut();
                match &mut fr {
                    Reader::Plain(p) => p.feed(&buf[..n]),
                    Reader::Sealed(s) => s.feed(&buf[..n]),
                }
                loop {
                    let f = match &mut fr {
                        Reader::Plain(p) => p.next(),
                        Reader::Sealed(s) => s.next(),
                    };
                    let Some(f) = f else { break };
                    // (what follows the challenge is sealed)
                    if let (Reader::Plain(p), Some(me)) = (&mut fr, me.upgrade()) {
                        let kx_public = *me.kx_public.borrow();
                        if let Some(opener) = keys_of(&mut i, me.raw, kx_public, &f) {
                            fr = Reader::Sealed(SealedReader::new(opener, p.take_rest()));
                        }
                    }
                    if f.ty == FT_JSON
                        && let Some(m) = read_json(&f.body)
                    {
                        let t = m.get("t").and_then(Value::as_str).unwrap_or("").to_string();
                        i.seen.push(t);
                        i.got.push(Value::Object(m));
                    }
                }
                if let Reader::Sealed(s) = &fr {
                    i.bad_seal |= s.bad;
                }
                drop(i);
                wake.notify_waiters();
            }
            inner.borrow_mut().closed = true;
            wake.notify_waiters();
            ended2.notify_one();
        });
        let writer = tokio::task::spawn_local(async move {
            loop {
                let mut got = None;
                let ended_now = first(ended.notified(), async { got = Some(rx.recv().await) }).await;
                match got {
                    Some(Some(b)) if !ended_now => {
                        if w.write_all(&b).await.is_err() {
                            return;
                        }
                    }
                    _ => {
                        let _ = w.shutdown().await;
                        return;
                    }
                }
            }
        });
        m.tasks.borrow_mut().extend([reader, writer]);
        m
    }

    /// One plain frame's bytes, sealed once this side's prove is sent.
    pub fn write(&self, b: &[u8]) {
        let mut i = self.inner.borrow_mut();
        let i = &mut *i;
        let bytes = match (i.sealing, i.tx.as_mut()) {
            (true, Some(tx)) => {
                let mut out = Vec::new();
                tx.seal_frame(b, &mut out).expect("a frame to seal");
                out
            }
            _ => b.to_vec(),
        };
        if let Some(tx) = self.out.borrow().as_ref() {
            let _ = tx.send(bytes);
        }
    }

    /// A message; the frames after a prove are sealed.
    pub fn send(&self, m: Value) {
        self.write(&json_frame(&m).unwrap());
        if m["t"] == "prove" {
            self.inner.borrow_mut().sealing = true;
        }
    }

    /// A hello of version `v`; its nonce.
    pub fn hello_v(&self, v: Value) -> [u8; NONCE_BYTES] {
        let mut nonce = [0u8; NONCE_BYTES];
        rand::fill(&mut nonce);
        let kx = KxSecret::fresh();
        *self.kx_public.borrow_mut() = kx.public();
        {
            let mut i = self.inner.borrow_mut();
            i.hello = Some((nonce, kx));
            i.tx = None;
            i.sealing = false;
        }
        let kx_public = *self.kx_public.borrow();
        self.send(json!({ "t": "hello", "v": v, "key": b64(&self.raw), "nonce": b64(&nonce), "kx": b64(&kx_public) }));
        nonce
    }

    pub fn hello(&self) -> [u8; NONCE_BYTES] {
        self.hello_v(json!(REGISTRY_WIRE_VERSION))
    }

    /// The start's transcript of this side's last hello and a challenge.
    pub fn transcript(&self, nonce: [u8; NONCE_BYTES], c: &Value) -> Transcript {
        Transcript {
            client_key: self.raw,
            relay_key: unb64(&c["key"]).try_into().unwrap(),
            client_nonce: nonce,
            relay_nonce: unb64(&c["nonce"]).try_into().unwrap(),
            client_kx: *self.kx_public.borrow(),
            relay_kx: unb64(&c["kx"]).try_into().unwrap(),
        }
    }

    /// A prove signed over `bytes`.
    pub fn prove_over(&self, bytes: &[u8]) {
        self.send(json!({ "t": "prove", "sig": b64(&self.key.sign(bytes).to_bytes()) }));
    }

    /// Hello, the challenge checked (the registry's key is `registry`, its signature over the link's context), the
    /// prove: the welcome's id.
    pub async fn start(&self, registry: &str) -> String {
        let nonce = self.hello();
        let c = self.msg("challenge").await;
        assert_eq!(c["v"], json!(REGISTRY_WIRE_VERSION));
        let raw: [u8; 32] = unb64(&c["key"]).try_into().unwrap();
        assert_eq!(key_id(&raw), registry, "the registry's key is its id");
        let t = self.transcript(nonce, &c);
        let sig = Signature::from_bytes(&unb64(&c["sig"]).try_into().unwrap());
        let rk = VerifyingKey::from_bytes(&raw).unwrap();
        assert!(rk.verify(&registry_handshake_bytes(Side::Relay, &t), &sig).is_ok(), "signed over the link's context");
        assert!(self.inner.borrow().tx.is_some(), "the challenge gave the keys");
        self.prove_over(&registry_handshake_bytes(Side::Client, &t));
        let w = self.msg("welcome").await;
        w["id"].as_str().unwrap().to_string()
    }

    pub fn counts() -> Value {
        json!({ "players": 1, "maxPlayers": 500, "matches": 0, "maxMatches": 250 })
    }

    /// A check-in of this build's relay wire and [`PROTO`].
    pub fn check_in(&self, address: &str) {
        self.send(json!({
            "t": "checkIn",
            "address": address,
            "wire": RELAY_WIRE_VERSION,
            "proto": PROTO,
            "counts": Member::counts(),
        }));
    }

    pub fn beat(&self) {
        self.send(json!({ "t": "beat", "counts": Member::counts() }));
    }

    pub fn closed(&self) -> bool {
        self.inner.borrow().closed
    }

    /// Whether the registry sent a message of this `t` at any time.
    pub fn saw(&self, t: &str) -> bool {
        self.inner.borrow().seen.iter().any(|s| s == t)
    }

    pub fn had(&self) -> String {
        self.inner.borrow().seen.join(", ")
    }

    /// Waits for `f` to give something; `None` after `ms`.
    pub async fn wait<T>(&self, ms: u64, mut f: impl FnMut(&mut Inner) -> Option<T>) -> Option<T> {
        let end = Instant::now() + Duration::from_millis(ms);
        loop {
            let n = self.wake.notified();
            let mut n = pin!(n);
            n.as_mut().enable();
            if let Some(x) = f(&mut self.inner.borrow_mut()) {
                return Some(x);
            }
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            let _ = tokio::time::timeout(left.min(Duration::from_millis(50)), n).await;
        }
    }

    /// The next message of this `t` (taken from the queue), or None when the link closes first or after `ms`.
    pub async fn msg_until(&self, t: &str, ms: u64) -> Option<Value> {
        self.wait(ms, |i| {
            if let Some(k) = i.got.iter().position(|m| m["t"] == t) {
                return Some(Some(i.got.remove(k)));
            }
            if i.closed { Some(None) } else { None }
        })
        .await
        .flatten()
    }

    pub async fn msg_in(&self, t: &str, ms: u64) -> Value {
        let m = self.msg_until(t, ms).await;
        m.unwrap_or_else(|| panic!("no {t}; closed {}; had {}", self.closed(), self.had()))
    }

    pub async fn msg(&self, t: &str) -> Value {
        self.msg_in(t, 2000).await
    }

    pub async fn closed_within(&self, ms: u64) {
        assert!(self.wait(ms, |i| i.closed.then_some(())).await.is_some(), "not closed; had {}", self.had());
    }

    /// The refused { why } that came within `ms`, the link closed after it.
    pub async fn refused_in(&self, ms: u64) -> String {
        let m = self.msg_in("refused", ms).await;
        self.closed_within(ms).await;
        m["why"].as_str().unwrap().to_string()
    }

    pub async fn refused(&self) -> String {
        self.refused_in(2000).await
    }
}
