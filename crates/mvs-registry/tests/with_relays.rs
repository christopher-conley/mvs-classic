//! A registry and real relays on 127.0.0.1: the relays check in, hear of each other and of one's going, and find the
//! registry again; and the registries a relay lets go: one of another key, one signed for the relay wire, one that
//! never answers the start, and one that goes quiet.

mod member;

use std::cell::{Cell, RefCell};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use member::{b64, new_key, run, sleep, unb64, until};
use mvs_protocol::registry_wire::{FromRegistry, REGISTRY_WIRE_VERSION, RelayEntry, registry_handshake_bytes};
use mvs_protocol::relay_seal::{KxSecret, TxSeal, derive, shared, split};
use mvs_protocol::relay_wire::{
    FrameReader, NONCE_BYTES, Side, Transcript, handshake_bytes, json_frame, key_id, read_json,
};
use mvs_protocol::version::PROTOCOL;
use mvs_registry::core::{Admission, Approved, Limits, Mode, Origin};
use mvs_registry::rules::Bans;
use mvs_registry::server::{Options, Running, prove_key, start_registry};
use mvs_relay::server::{Options as RelayOptions, RegistryOptions, Relay, start_relay};
use serde_json::{Map, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A relay's log lines.
type Lines = Rc<RefCell<Vec<String>>>;

const LOST: &str = "registry: lost: ";
const CHECKED_IN: &str = "registry: checked in";

/// A port of 127.0.0.1 that nothing listens on now.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// An open registry on 127.0.0.1 (`port` 0 picks one) that several relays of 127.0.0.1 fit, dialed again as often as
/// a check's waits have it.
fn registry(port: u16, key_file: Option<PathBuf>) -> Running {
    start_registry(Options {
        port,
        host: "127.0.0.1".into(),
        key_file,
        admission: Admission { mode: Mode::Open, approved: Vec::new(), bans: Bans::new(Vec::new()) },
        limits: Limits { per_address: 64, connects_per_minute: 60000.0, recheck_ms: 20.0, ..Limits::default() },
        sweep_ms: 20.0,
        ..Options::default()
    })
    .unwrap()
}

/// The relay's id on the registry's allow list at its `127.0.0.1:port`: loopback is dialed only so. Called before
/// the next await, so it is there before the relay's link first runs.
fn approve(reg: &Running, relay: &Relay) {
    let a = Approved {
        id: relay.id.clone(),
        address: Some(format!("127.0.0.1:{}", relay.port)),
        name: None,
        origin: Origin::Config,
    };
    reg.with_core(|core, now| core.approve(a, now));
}

/// A registry link at `address` whose key is `id`, every interval in tens of ms.
fn link(address: &str, id: &str, port: u16) -> RegistryOptions {
    let mut o = RegistryOptions::new(address, id, &format!("127.0.0.1:{port}"));
    o.beat_ms = 50.0;
    o.silent_ms = 500.0;
    o.start_ms = 500.0;
    o.retry_ms = (10.0, 40.0);
    o
}

/// A relay on 127.0.0.1, its registry link what `registry` makes of its port; its log kept.
fn relay(registry: impl Fn(u16) -> Option<RegistryOptions>) -> (Relay, Lines) {
    for _ in 0..20 {
        let port = free_port();
        let lines = Lines::default();
        let keep = lines.clone();
        let o = RelayOptions {
            port,
            host: "127.0.0.1".into(),
            log: Some(Box::new(move |l| keep.borrow_mut().push(l.to_string()))),
            hosted: None,
            registry: registry(port),
            ..RelayOptions::default()
        };
        match start_relay(o) {
            Ok(r) => return (r, lines),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(e) => panic!("relay not started: {e}"),
        }
    }
    panic!("no free port")
}

fn count(lines: &Lines, starts: &str) -> usize {
    lines.borrow().iter().filter(|l| l.starts_with(starts)).count()
}

fn has(lines: &Lines, line: &str) -> bool {
    lines.borrow().iter().any(|l| l == line)
}

fn listed(reg: &Running) -> Vec<RelayEntry> {
    reg.with_core(|core, _| core.relays(PROTOCOL))
}

fn at(relay: &Relay) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::LOCALHOST, relay.port)
}

/// A test registry's side of one connection: its frames read plain.
struct Fake {
    s: TcpStream,
    fr: FrameReader,
}

impl Fake {
    async fn accept(l: &TcpListener) -> Fake {
        Fake { s: l.accept().await.unwrap().0, fr: FrameReader::new() }
    }

    /// The next plain frame's message; None when the relay closes first.
    async fn message(&mut self) -> Option<Map<String, Value>> {
        let mut buf = [0u8; 4096];
        loop {
            if let Some(f) = self.fr.next() {
                return read_json(&f.body);
            }
            let n = self.s.read(&mut buf).await.ok()?;
            if n == 0 {
                return None;
            }
            self.fr.feed(&buf[..n]);
        }
    }

    /// The challenge to `hello` from `key`, its signature over `sign`'s bytes; the registry side's sealer.
    async fn challenge(
        &mut self,
        key: &SigningKey,
        hello: &Map<String, Value>,
        sign: fn(Side, &Transcript) -> Vec<u8>,
    ) -> TxSeal {
        let raw = key.verifying_key().to_bytes();
        let mut nonce = [0u8; NONCE_BYTES];
        rand::fill(&mut nonce);
        let kx = KxSecret::fresh();
        let t = Transcript {
            client_key: unb64(&hello["key"]).try_into().unwrap(),
            relay_key: raw,
            client_nonce: unb64(&hello["nonce"]).try_into().unwrap(),
            relay_nonce: nonce,
            client_kx: unb64(&hello["kx"]).try_into().unwrap(),
            relay_kx: kx.public(),
        };
        let c = FromRegistry::Challenge {
            v: REGISTRY_WIRE_VERSION,
            key: b64(&raw),
            nonce: b64(&nonce),
            kx: b64(&t.relay_kx),
            sig: b64(&key.sign(&sign(Side::Relay, &t)).to_bytes()),
        };
        self.s.write_all(&json_frame(&c).unwrap()).await.unwrap();
        let secret = shared(kx, &t.client_kx).unwrap();
        split(&derive(&secret, &t), Side::Relay).0
    }
}

#[test]
fn two_relays_see_each_other() {
    run(async {
        let reg = registry(0, None);
        let address = format!("127.0.0.1:{}", reg.port);
        let (a, _) = relay(|p| Some(link(&address, &reg.id, p)));
        approve(&reg, &a);
        let (b, _) = relay(|p| Some(link(&address, &reg.id, p)));
        approve(&reg, &b);
        until("each hears of the other", 3000, || a.registry_relays().len() == 1 && b.registry_relays().len() == 1)
            .await;
        let (heard_a, heard_b) = (a.registry_relays(), b.registry_relays());
        assert_eq!(
            (heard_a[0].id.as_str(), heard_a[0].address.clone()),
            (b.id.as_str(), format!("127.0.0.1:{}", b.port))
        );
        assert_eq!(
            (heard_b[0].id.as_str(), heard_b[0].address.clone()),
            (a.id.as_str(), format!("127.0.0.1:{}", a.port))
        );
        assert!(heard_a[0].approved && a.registry_up() && b.registry_up());
        a.close().await;
        b.close().await;
        reg.close().await;
    });
}

#[test]
fn a_stopped_relay_is_gone() {
    run(async {
        let reg = registry(0, None);
        let address = format!("127.0.0.1:{}", reg.port);
        let (a, _) = relay(|p| Some(link(&address, &reg.id, p)));
        approve(&reg, &a);
        let (b, _) = relay(|p| Some(link(&address, &reg.id, p)));
        approve(&reg, &b);
        until("a hears of b", 3000, || a.registry_relays().len() == 1).await;
        b.close().await;
        until("b is gone from a's list", 2000, || a.registry_relays().is_empty()).await;
        assert!(a.registry_up(), "a's own link stays");
        a.close().await;
        reg.close().await;
    });
}

#[test]
fn a_relay_with_no_block_says_nothing_of_one() {
    run(async {
        let (r, lines) = relay(|_| None);
        assert_eq!(prove_key(at(&r), 2000.0).await, Some(r.id.clone()));
        sleep(100).await;
        assert!(!lines.borrow().iter().any(|l| l.contains("registry")), "{:?}", lines.borrow());
        assert!(!r.registry_up() && r.registry_relays().is_empty());
        r.close().await;
    });
}

#[test]
fn a_relay_starts_with_no_registry_there() {
    run(async {
        let closed = free_port();
        let (r, lines) = relay(|p| Some(link(&format!("127.0.0.1:{closed}"), &key_id(&[7; 32]), p)));
        assert_eq!(prove_key(at(&r), 2000.0).await, Some(r.id.clone()), "the relay serves players at once");
        // (the tries at 0, 10, 30 and 70 ms, and more: past three retries)
        sleep(200).await;
        assert_eq!(count(&lines, LOST), 1, "one line for the outage, not one a try: {:?}", lines.borrow());
        assert!(has(&lines, "registry: lost: could not connect; trying again"), "{:?}", lines.borrow());
        assert!(!r.registry_up());
        // (it is still trying: a listener on that port now is dialed)
        let l = TcpListener::bind(("127.0.0.1", closed)).await.unwrap();
        let dialed = tokio::time::timeout(Duration::from_millis(1000), l.accept()).await;
        assert!(dialed.is_ok(), "dialed again");
        assert_eq!(count(&lines, LOST), 1, "{:?}", lines.borrow());
        r.close().await;
    });
}

#[test]
fn a_relay_finds_the_registry_again() {
    run(async {
        let file = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("with-relays-{}.key", std::process::id()));
        let _ = std::fs::remove_file(&file);
        let mut reg = registry(0, Some(file.clone()));
        let (port, id) = (reg.port, reg.id.clone());
        let address = format!("127.0.0.1:{port}");
        let (r, lines) = relay(|p| Some(link(&address, &id, p)));
        approve(&reg, &r);
        until("listed", 3000, || r.registry_up() && listed(&reg).iter().any(|e| e.id == r.id)).await;
        // (two outages: each has its one line, the second after the relay checked in again)
        for outage in 1..=2 {
            reg.close().await;
            until("the link lost", 2000, || !r.registry_up() && count(&lines, LOST) == outage).await;
            sleep(150).await;
            reg = registry(port, Some(file.clone()));
            assert_eq!(reg.id, id, "the same key");
            approve(&reg, &r);
            until("listed again", 3000, || r.registry_up() && listed(&reg).iter().any(|e| e.id == r.id)).await;
            assert_eq!(count(&lines, LOST), outage, "{:?}", lines.borrow());
            assert_eq!(count(&lines, CHECKED_IN), outage + 1, "{:?}", lines.borrow());
        }
        let _ = std::fs::remove_file(&file);
        assert_eq!(count(&lines, LOST), 2, "{:?}", lines.borrow());
        assert_eq!(count(&lines, CHECKED_IN), 3, "{:?}", lines.borrow());
        r.close().await;
        reg.close().await;
    });
}

#[test]
fn a_registry_of_another_key_is_refused_by_the_relay() {
    run(async {
        let reg = registry(0, None);
        let address = format!("127.0.0.1:{}", reg.port);
        let other = key_id(&new_key().verifying_key().to_bytes());
        let (r, lines) = relay(|p| Some(link(&address, &other, p)));
        approve(&reg, &r);
        let named = "registry: lost: the registry at that address proved another key; trying again";
        until("the relay names it", 2000, || has(&lines, named)).await;
        sleep(150).await;
        assert!(listed(&reg).is_empty(), "the registry lists nothing from that relay");
        assert!(!r.registry_up());
        assert_eq!(count(&lines, LOST), 1, "{:?}", lines.borrow());
        r.close().await;
        reg.close().await;
    });
}

#[test]
fn a_registry_that_signs_for_the_relay_wire_is_refused() {
    run(async {
        let key = new_key();
        let id = key_id(&key.verifying_key().to_bytes());
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = l.local_addr().unwrap().to_string();
        let (r, lines) = relay(|p| Some(link(&address, &id, p)));
        let dialed = tokio::time::timeout(Duration::from_millis(2000), Fake::accept(&l)).await;
        let mut fake = dialed.expect("the relay dials");
        let hello = fake.message().await.expect("a hello");
        assert_eq!(hello["t"], "hello");
        fake.challenge(&key, &hello, handshake_bytes).await;
        let mut buf = [0u8; 256];
        let after = tokio::time::timeout(Duration::from_millis(300), fake.s.read(&mut buf)).await;
        assert!(!matches!(after, Ok(Ok(n)) if n > 0), "no prove sent");
        until("bad signature", 1000, || has(&lines, "registry: lost: bad signature; trying again")).await;
        assert!(!r.registry_up());
        r.close().await;
    });
}

#[test]
fn a_start_that_gets_no_answer_is_given_up() {
    run(async {
        let l = Rc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let address = l.local_addr().unwrap().to_string();
        let held = Rc::new(RefCell::new(Vec::new()));
        let accepted = Rc::new(Cell::new(0));
        let (lh, hh, ah) = (l.clone(), held.clone(), accepted.clone());
        let listener = tokio::task::spawn_local(async move {
            loop {
                let (s, _) = lh.accept().await.unwrap();
                hh.borrow_mut().push(s);
                ah.set(ah.get() + 1);
            }
        });
        let (r, lines) = relay(|p| {
            let mut o = link(&address, &key_id(&[7; 32]), p);
            o.start_ms = 50.0;
            Some(o)
        });
        assert_eq!(prove_key(at(&r), 2000.0).await, Some(r.id.clone()), "the relay serves players meanwhile");
        until("dialed again", 2000, || accepted.get() >= 2).await;
        assert!(has(&lines, "registry: lost: the start took too long; trying again"), "{:?}", lines.borrow());
        assert_eq!(count(&lines, LOST), 1, "{:?}", lines.borrow());
        listener.abort();
        r.close().await;
    });
}

#[test]
fn a_registry_that_goes_quiet_is_let_go() {
    run(async {
        let key = new_key();
        let id = key_id(&key.verifying_key().to_bytes());
        let l = Rc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let address = l.local_addr().unwrap().to_string();
        let accepted = Rc::new(Cell::new(0));
        let (lh, ah) = (l.clone(), accepted.clone());
        let listener = tokio::task::spawn_local(async move {
            let mut held = Vec::new();
            loop {
                let mut fake = Fake::accept(&lh).await;
                ah.set(ah.get() + 1);
                if ah.get() == 1 {
                    // (the start as the registry has it, then nothing: no beat is answered)
                    let hello = fake.message().await.unwrap();
                    let mut tx = fake.challenge(&key, &hello, registry_handshake_bytes).await;
                    let prove = fake.message().await.unwrap();
                    assert_eq!(prove["t"], "prove");
                    let mut out = Vec::new();
                    let welcome = FromRegistry::Welcome { id: key_id(&hello_key(&hello)) };
                    tx.seal_frame(&json_frame(&welcome).unwrap(), &mut out).unwrap();
                    fake.s.write_all(&out).await.unwrap();
                }
                held.push(fake);
            }
        });
        let (r, lines) = relay(|p| {
            let mut o = link(&address, &id, p);
            o.beat_ms = 20.0;
            o.silent_ms = 80.0;
            Some(o)
        });
        until("checked in", 2000, || r.registry_up()).await;
        until("let go", 1000, || !r.registry_up()).await;
        until("a second connection", 1000, || accepted.get() >= 2).await;
        assert!(has(&lines, CHECKED_IN), "{:?}", lines.borrow());
        assert!(has(&lines, "registry: lost: the registry went quiet; trying again"), "{:?}", lines.borrow());
        listener.abort();
        r.close().await;
    });
}

fn hello_key(hello: &Map<String, Value>) -> Vec<u8> {
    unb64(&hello["key"])
}
